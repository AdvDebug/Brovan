using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiLineTo : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hdc = Instance.WinHelper.GetArg(0);
            int X = unchecked((int)Instance.WinHelper.GetArg(1));
            int Y = unchecked((int)Instance.WinHelper.GetArg(2));

            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.WinHelper.ReadDcCurrentPosition(Hdc, out int StartX, out int StartY);
            ulong PenHandle = Instance.WinHelper.ReadDcSelectedPen(Hdc);
            Win32kPenBrush Pen = Win32kHelper.ResolvePenBrush(Instance, PenHandle, true);

            Instance.WinHelper.EnqueueGdiLine(Hwnd, StartX, StartY, X, Y, Pen.ColorRef, Pen.PenWidth);
            Instance.WinHelper.WriteDcCurrentPosition(Hdc, X, Y);

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
