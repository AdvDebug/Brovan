using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserBeginPaint : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong PaintStructPtr = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            ulong Hdc = Win32kHelper.CreateDeviceContext(Instance, Hwnd, false, true);
            if (Hdc == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            List<GdiClipRect> PaintArea = Win32kHelper.GetPaintArea(Instance, Window, out GdiClipRect Bounds);

            bool Owed = Window.PaintPending;
            bool Erase = Window.SendEraseBackground;
            if (Erase)
            {
                Window.SendEraseBackground = false;
                Window.BackgroundUnerased = false;
            }

            if (!Win32kHelper.WritePaintStruct(Instance, PaintStructPtr, Hdc, Bounds, Window.BackgroundUnerased))
            {
                Win32kHelper.ReleaseDeviceContext(Instance, Hdc);
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);
            }

            Window.UpdateDirty = false;
            Win32kHelper.SetDcPaintArea(Instance, Hdc, PaintArea);
            Win32kHelper.ClearUpdateArea(Instance, Window);
            Instance.SetLastWinError(0);

            if (Erase && Owed && !Window.Minimized && PaintArea.Count != 0)
            {
                WinPaintBegin Paint = new WinPaintBegin { Hwnd = Hwnd, Hdc = Hdc, PaintStruct = PaintStructPtr };
                if (Win32kHelper.SendEraseBackground(Instance, Window, Paint))
                    return NTSTATUS.STATUS_SUCCESS;

                Window.BackgroundUnerased = true;
                Win32kHelper.WritePaintErase(Instance, PaintStructPtr, true);
            }

            Instance.SetRawSyscallReturn(Hdc);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
