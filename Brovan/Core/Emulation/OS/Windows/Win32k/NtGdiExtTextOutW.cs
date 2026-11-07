using System.Runtime.InteropServices;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiExtTextOutW : IWinSyscall
    {
        private const uint MaxCharacters = 0xFFFF;

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

            if (Count > MaxCharacters)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // Glyph indices are any 16-bit value, so the units are kept as read.
            string Text = string.Empty;
            if (StringPtr != 0 && Count > 0)
            {
                Span<byte> Units = Instance.WinHelper.ReadMemorySpan(StringPtr, Count * 2);
                if (Units.IsEmpty)
                {
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                Text = new string(MemoryMarshal.Cast<byte, char>(Units));
            }

            GdiClipRect? Rect = null;
            if (RectPtr != 0 && Win32kHelper.TryReadGuestRect(Instance, RectPtr, out GdiClipRect Given))
                Rect = Given;

            uint Align = Instance.WinHelper.ReadDcTextAlign(Hdc);
            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd == 0)
            {
                Win32kHelper.TryRenderTextToDcBitmap(Instance, Hdc, Text, X, Y, Options, Align, Rect);
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

            Win32kHelper.EnqueueWindowText(Instance, Hwnd, Hdc, Text, X, Y, Options, Align, Bounds);
            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
