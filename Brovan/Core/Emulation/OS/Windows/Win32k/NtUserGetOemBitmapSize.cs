using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetOemBitmapSize : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            int Index = unchecked((int)Instance.WinHelper.GetArg(0));
            ulong SizePtr = Instance.WinHelper.GetArg(1);

            if (SizePtr == 0 || !Win32kHelper.TryGetOemBitmapSize(Index, out int Width, out int Height))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.IsRegionMapped(SizePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance._emulator.WriteMemory(SizePtr, (uint)Width, 4);
            Instance._emulator.WriteMemory(SizePtr + 4, (uint)Height, 4);

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
