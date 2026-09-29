using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserScrollWindowEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            int Dx = unchecked((int)Instance.WinHelper.GetArg32(1));
            int Dy = unchecked((int)Instance.WinHelper.GetArg32(2));
            ulong ScrollPtr = Instance.WinHelper.GetArg(3);
            ulong ClipPtr = Instance.WinHelper.GetArg(4);
            ulong Region = Instance.WinHelper.GetArg(5);
            ulong UpdatePtr = Instance.WinHelper.GetArg(6);
            uint Flags = Instance.WinHelper.GetArg32(7);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.TryReadOptionalRect(Instance, ScrollPtr, out GdiClipRect? Scroll)
                || !Win32kHelper.TryReadOptionalRect(Instance, ClipPtr, out GdiClipRect? Clip))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_NOACCESS);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Result = Win32kHelper.ScrollWindow(Instance, Window, Dx, Dy, Scroll, Clip, Region, UpdatePtr != 0, Flags,
                out GdiClipRect UpdateRect, out WinScrollChildMoves Moves);

            if (Moves != null)
            {
                Moves.Result = Result;
                Moves.UpdateAddress = UpdatePtr;
                Moves.UpdateRect = UpdateRect;
                if (Win32kHelper.SendScrollChildMoves(Instance, Moves))
                    return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(Win32kHelper.FinishScrollWindow(Instance, UpdatePtr, UpdateRect, Result));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
