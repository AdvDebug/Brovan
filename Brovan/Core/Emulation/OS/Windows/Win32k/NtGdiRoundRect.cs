using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiRoundRect : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hdc = Instance.WinHelper.GetArg(0);
            int Left = unchecked((int)Instance.WinHelper.GetArg(1));
            int Top = unchecked((int)Instance.WinHelper.GetArg(2));
            int Right = unchecked((int)Instance.WinHelper.GetArg(3));
            int Bottom = unchecked((int)Instance.WinHelper.GetArg(4));
            int Width = unchecked((int)Instance.WinHelper.GetArg(5));
            int Height = unchecked((int)Instance.WinHelper.GetArg(6));

            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kPenBrush Pen = Win32kHelper.ResolvePenBrush(Instance, Instance.WinHelper.ReadDcSelectedPen(Hdc), true);
            Win32kPenBrush Brush = Win32kHelper.ResolvePenBrush(Instance, Instance.WinHelper.ReadDcSelectedBrush(Hdc), false);

            Instance.WinHelper.EnqueueGdiShape(Hwnd, GdiPrimitiveKind.RoundRect, Left, Top, Right, Bottom, Pen.ColorRef, Pen.PenWidth, Brush.ColorRef, Width, Height);

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
