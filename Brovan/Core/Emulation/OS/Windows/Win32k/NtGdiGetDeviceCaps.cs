namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetDeviceCaps : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            int Index = unchecked((int)Instance.WinHelper.GetArg(1));
            Instance.SetRawSyscallReturn(unchecked((ulong)(uint)GetDeviceCapability(Index)));
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static int GetDeviceCapability(int Index)
        {
            return Index switch
            {
                2 => 1, // TECHNOLOGY: DT_RASDISPLAY
                4 => 320, // HORZSIZE
                6 => 180, // VERTSIZE
                8 => 1920, // HORZRES
                10 => 1080, // VERTRES
                12 => 32, // BITSPIXEL
                14 => 1, // PLANES
                24 => -1, // NUMCOLORS
                88 => 96, // LOGPIXELSX
                90 => 96, // LOGPIXELSY
                116 => 60, // VREFRESH
                121 => 0x00000003, // COLORMGMTCAPS: CM_DEVICE_ICM | CM_GAMMA_RAMP
                _ => 0,
            };
        }
    }
}
