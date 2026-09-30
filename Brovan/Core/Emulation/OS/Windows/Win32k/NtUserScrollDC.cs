using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserScrollDC : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int Dx = unchecked((int)Instance.WinHelper.GetArg32(1));
            int Dy = unchecked((int)Instance.WinHelper.GetArg32(2));
            ulong ScrollPtr = Instance.WinHelper.GetArg(3);
            ulong ClipPtr = Instance.WinHelper.GetArg(4);
            ulong Region = Instance.WinHelper.GetArg(5);
            ulong UpdatePtr = Instance.WinHelper.GetArg(6);

            if (!Win32kHelper.TryReadOptionalRect(Instance, ScrollPtr, out GdiClipRect? Scroll)
                || !Win32kHelper.TryReadOptionalRect(Instance, ClipPtr, out GdiClipRect? Clip))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

            int Result = Win32kHelper.ScrollDc(Instance, Hdc, Dx, Dy, Scroll, Clip, Region, UpdatePtr != 0, out GdiClipRect UpdateRect);

            if (UpdatePtr != 0 && !Win32kHelper.TryWriteGuestRect(Instance, UpdatePtr, UpdateRect))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

            Instance.SetBooleanSyscallReturn(Result != Win32kHelper.RegionError);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
