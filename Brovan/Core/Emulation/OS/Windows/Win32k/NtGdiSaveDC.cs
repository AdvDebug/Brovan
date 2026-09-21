using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiSaveDC : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int Level = Win32kHelper.SaveDeviceContext(Instance, Hdc);

            Instance.SetLastWinError(Level == 0 ? Win32kHelper.ERROR_INVALID_HANDLE : Win32kHelper.ERROR_SUCCESS);
            Instance.SetRawSyscallReturn((ulong)(uint)Level);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
