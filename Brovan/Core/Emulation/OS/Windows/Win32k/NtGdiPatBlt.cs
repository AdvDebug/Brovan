using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiPatBlt : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hdc = Instance.WinHelper.GetArg64(0);
            int X = unchecked((int)Instance.WinHelper.GetArg64(1, true));
            int Y = unchecked((int)Instance.WinHelper.GetArg64(2, true));
            int Width = unchecked((int)Instance.WinHelper.GetArg64(3, true));
            int Height = unchecked((int)Instance.WinHelper.GetArg64(4, true));
            uint Rop = (uint)Instance.WinHelper.GetArg64(5, true);

            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong BrushHandle = Instance.WinHelper.ReadDcSelectedBrush(Hdc);
            Win32kPenBrush Brush = Win32kHelper.ResolvePenBrush(Instance, BrushHandle, false);
            Instance.WinHelper.EnqueueGdiFillRect(Hwnd, X, Y, X + Width, Y + Height, Brush.ColorRef, Rop);

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
