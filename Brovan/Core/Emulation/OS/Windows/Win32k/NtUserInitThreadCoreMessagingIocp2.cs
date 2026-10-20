using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserInitThreadCoreMessagingIocp2 : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong SlotPtr = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            if (SlotPtr == 0)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            if (!Win32kHelper.IsOwnedByCurrentThread(Instance, Window))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_ACCESS_DENIED);

            if (Instance.WinHelper.PointerSize != 8)
            {
                Brovan.Core.Helpers.Utils.LogError("[-] win32k: the CoreMessaging queue port is served to x64 guests only.");
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOT_SUPPORTED);
            }

            WindowsThreadState State = WinEmulatedThread.GetState(Instance.CurrentThread);
            int Slot = 0;
            while (true)
            {
                if (Slot >= Win32kQueuePort.SlotCount)
                    return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_ALREADY_INITIALIZED);

                ulong Registered = State.CoreMessagingWindows?[Slot] ?? 0;
                if (Registered == 0)
                    break;

                if (Registered == Hwnd)
                    return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

                Slot++;
            }

            Win32kQueuePort.EnsurePort(Instance, State);
            State.CoreMessagingWindows[Slot] = Hwnd;
            if (!Instance.WinHelper.WriteUInt32(SlotPtr, (uint)Slot))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

            Instance.SetRawSyscallReturn(State.QueuePortHandle);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
