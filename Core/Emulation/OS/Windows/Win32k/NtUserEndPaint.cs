using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEndPaint : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            ulong PaintStructPtr = Instance.WinHelper.GetArg64(1);

            if (Instance.WinHelper.GetWindow(Hwnd) == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (PaintStructPtr != 0 && Instance.IsRegionMapped(PaintStructPtr, 8))
            {
                ulong Hdc = Instance.ReadMemoryULong(PaintStructPtr);
                Win32kHelper.ReleaseDeviceContext(Instance, Hdc);
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
