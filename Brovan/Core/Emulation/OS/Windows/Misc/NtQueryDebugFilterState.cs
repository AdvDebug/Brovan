namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryDebugFilterState : IWinSyscall
    {
        private const uint ComponentCount = 0x9C;
        private const uint InfoLevel = 3;

        // With no Debug Print Filter key, NT prints only errors (Kd_WIN2000_Mask).
        private const uint EnabledLevels = 1;

        // NT treats a level up to 31 as a bit number and a larger one as a mask. The result is TRUE or FALSE, not a status.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint ComponentId = (uint)Instance.WinHelper.GetArg(0);
            uint Level = ComponentId < ComponentCount ? (uint)Instance.WinHelper.GetArg(1) : InfoLevel;
            uint Mask = Level <= 31 ? 1u << (int)Level : Level;
            return (Mask & EnabledLevels) != 0 ? (NTSTATUS)1 : NTSTATUS.STATUS_SUCCESS;
        }
    }
}
