using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiSetBoundsRect : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong RectPtr = Instance.WinHelper.GetArg(1);
            uint Flags = (uint)Instance.WinHelper.GetArg(2);

            int Left = 0, Top = 0, Right = 0, Bottom = 0;
            bool HasRect = RectPtr != 0;

            if (HasRect)
            {
                if (!Instance.IsRegionMapped(RectPtr, 16))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Left = unchecked((int)Instance._emulator.ReadMemoryUInt(RectPtr));
                Top = unchecked((int)Instance._emulator.ReadMemoryUInt(RectPtr + 4));
                Right = unchecked((int)Instance._emulator.ReadMemoryUInt(RectPtr + 8));
                Bottom = unchecked((int)Instance._emulator.ReadMemoryUInt(RectPtr + 12));
            }

            if (!Win32kHelper.TrySetDcBounds(Instance, Hdc, Flags, HasRect, Left, Top, Right, Bottom, out uint Previous))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
