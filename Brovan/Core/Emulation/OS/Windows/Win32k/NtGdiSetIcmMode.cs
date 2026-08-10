using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    /// <summary>
    /// Brovan has no colour management, so only the modes that leave ICM disabled succeed and gdi32 falls back
    /// to passing bitmap bits through untransformed.
    /// </summary>
    internal class NtGdiSetIcmMode : IWinSyscall
    {
        private const uint IcmSetMode = 1;
        private const uint IcmOff = 1;
        private const uint IcmQuery = 3;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Action = Instance.WinHelper.GetArg32(1);
            uint Mode = Instance.WinHelper.GetArg32(2);

            bool Supported = Action != IcmSetMode || Mode == IcmOff || Mode == IcmQuery;
            Instance.SetRawSyscallReturn(Supported ? IcmOff : 0u);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
