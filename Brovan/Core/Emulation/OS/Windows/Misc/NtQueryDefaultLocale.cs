namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryDefaultLocale : IWinSyscall
    {
        private const uint EnglishUnitedStates = 0x0409;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong LocaleIdPtr = Instance.WinHelper.GetArg(1);

            if (LocaleIdPtr == 0 || !Instance.IsRegionMapped(LocaleIdPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance._emulator.WriteMemory(LocaleIdPtr, EnglishUnitedStates, 4);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
