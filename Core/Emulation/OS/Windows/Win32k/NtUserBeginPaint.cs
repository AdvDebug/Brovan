using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserBeginPaint : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            ulong PaintStructPtr = Instance.WinHelper.GetArg64(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Hdc = Win32kHelper.CreateDeviceContext(Instance, Hwnd, false, true);
            if (Hdc == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.WritePaintStruct(Instance, PaintStructPtr, Hdc, Window))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Window.Dirty = false;
            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Hdc);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
