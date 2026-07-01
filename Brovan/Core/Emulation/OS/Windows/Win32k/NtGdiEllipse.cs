using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiEllipse : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hdc = Instance.WinHelper.GetArg64(0);
            int Left = unchecked((int)Instance.WinHelper.GetArg64(1, true));
            int Top = unchecked((int)Instance.WinHelper.GetArg64(2, true));
            int Right = unchecked((int)Instance.WinHelper.GetArg64(3, true));
            int Bottom = unchecked((int)Instance.WinHelper.GetArg64(4, true));

            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kPenBrush Pen = Win32kHelper.ResolvePenBrush(Instance, Instance.WinHelper.ReadDcSelectedPen(Hdc), true);
            Win32kPenBrush Brush = Win32kHelper.ResolvePenBrush(Instance, Instance.WinHelper.ReadDcSelectedBrush(Hdc), false);

            Instance.WinHelper.EnqueueGdiShape(Hwnd, GdiPrimitiveKind.Ellipse, Left, Top, Right, Bottom, Pen.ColorRef, Pen.PenWidth, Brush.ColorRef);

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
