using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetPointerType : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint PointerId = (uint)Instance.WinHelper.GetArg(0);
            ulong TypePtr = Instance.WinHelper.GetArg(1);

            if (PointerId != Win32kHelper.PointerIdMouse || TypePtr == 0 || !Instance.IsRegionMapped(TypePtr, 4))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance._emulator.WriteMemory(TypePtr, Win32kHelper.PointerTypeMouse, 4);

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
