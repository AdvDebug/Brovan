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

            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd == 0)
            {
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            string Text = string.Empty;
            if (StringPtr != 0 && Count > 0)
            {
                Text = Instance._emulator.ReadMemoryString(StringPtr, (int)(Count * 2), System.Text.Encoding.Unicode)?.TrimEnd('\0') ?? string.Empty;
            }

            int RectLeft = 0, RectTop = 0, RectRight = 0, RectBottom = 0;
            if (RectPtr != 0 && Instance.IsRegionMapped(RectPtr, 16))
            {
                RectLeft = unchecked((int)Instance.ReadMemoryUInt(RectPtr));
                RectTop = unchecked((int)Instance.ReadMemoryUInt(RectPtr + 4));
                RectRight = unchecked((int)Instance.ReadMemoryUInt(RectPtr + 8));
                RectBottom = unchecked((int)Instance.ReadMemoryUInt(RectPtr + 12));
            }
            else
            {
                RectRight = (int)Window.Width;
                RectBottom = (int)Window.Height;
            }

            Instance.WinHelper.EnqueueTextRender(Hwnd, Text, X, Y, RectLeft, RectTop, RectRight, RectBottom, Options);

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
