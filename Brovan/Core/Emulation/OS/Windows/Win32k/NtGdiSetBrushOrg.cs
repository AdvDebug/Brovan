using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiSetBrushOrg : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int X = unchecked((int)Instance.WinHelper.GetArg(1));
            int Y = unchecked((int)Instance.WinHelper.GetArg(2));
            ulong PreviousPtr = Instance.WinHelper.GetArg(3);

            if (!Instance.WinHelper.ReadDcBrushOrigin(Hdc, out int PreviousX, out int PreviousY))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (PreviousPtr != 0)
            {
                if (!Instance.IsRegionMapped(PreviousPtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(PreviousPtr, unchecked((uint)PreviousX), 4);
                Instance._emulator.WriteMemory(PreviousPtr + 4, unchecked((uint)PreviousY), 4);
            }

            Instance.WinHelper.WriteDcBrushOrigin(Hdc, X, Y);
            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
