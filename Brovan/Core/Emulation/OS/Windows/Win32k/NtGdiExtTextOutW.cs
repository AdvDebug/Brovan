using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiExtTextOutW : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hdc = Instance.WinHelper.GetArg(0);
            int X = unchecked((int)Instance.WinHelper.GetArg(1));
            int Y = unchecked((int)Instance.WinHelper.GetArg(2));
            uint Options = (uint)Instance.WinHelper.GetArg(3);
            ulong RectPtr = Instance.WinHelper.GetArg(4);
            ulong StringPtr = Instance.WinHelper.GetArg(5);
            uint Count = (uint)Instance.WinHelper.GetArg(6);
            ulong DxPtr = Instance.WinHelper.GetArg(7);

            string Text = string.Empty;
            if (StringPtr != 0 && Count > 0)
            {
                Text = Instance._emulator.ReadMemoryString(StringPtr, (int)(Count * 2), System.Text.Encoding.Unicode)?.TrimEnd('\0') ?? string.Empty;
            }

            GdiClipRect? Rect = null;
            if (RectPtr != 0 && Win32kHelper.TryReadGuestRect(Instance, RectPtr, out GdiClipRect Given))
                Rect = Given;

            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd == 0)
            {
                Win32kHelper.TryRenderTextToDcBitmap(Instance, Hdc, Text, X, Y, Options, Rect);
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Rect is not GdiClipRect Bounds)
            {
                Win32kHelper.GetClientSize(Instance, Window, out int ClientWidth, out int ClientHeight);
                Bounds = new GdiClipRect { Right = ClientWidth, Bottom = ClientHeight };
            }

            Instance.WinHelper.EnqueueTextRender(Hwnd, Hdc, Win32kHelper.ResolveDcFont(Instance, Hdc), Text, X, Y, Bounds.Left, Bounds.Top, Bounds.Right, Bounds.Bottom,
                Options);

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
