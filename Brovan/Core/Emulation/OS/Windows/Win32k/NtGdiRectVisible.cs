using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiRectVisible : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong RectPtr = Instance.WinHelper.GetArg(1);

            if (!Win32kHelper.TryReadGuestRect(Instance, RectPtr, out GdiClipRect Rect))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool Visible = Win32kHelper.IsDcAreaVisible(Instance, Hdc, Math.Min(Rect.Left, Rect.Right), Math.Min(Rect.Top, Rect.Bottom), Math.Max(Rect.Left, Rect.Right), Math.Max(Rect.Top, Rect.Bottom));
            Instance.SetRawSyscallReturn(Visible ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
