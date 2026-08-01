using System.Runtime.InteropServices;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetCursorPos : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PointPtr = Instance.WinHelper.GetArg(0);
            if (PointPtr == 0 || !Instance.IsRegionMapped(PointPtr, (ulong)Marshal.SizeOf<POINT>()))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kHelper.GetCursorPosition(Instance, out int X, out int Y);

            POINT Point = new POINT { X = X, Y = Y };
            if (!StructSerializer.WriteStruct(Instance, PointPtr, Point).Success)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
