namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetDeviceCaps : IWinSyscall
    {
        private const int HORZSIZE = 4;
        private const int VERTSIZE = 6;
        private const int HORZRES = 8;
        private const int VERTRES = 10;
        private const int LOGPIXELSX = 88;
        private const int LOGPIXELSY = 90;

        private const int TenthsOfMillimetrePerInch = 254;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            int Index = unchecked((int)Instance.WinHelper.GetArg(1));
            Instance.SetRawSyscallReturn(unchecked((ulong)(uint)GetDeviceCapability(Instance, Index)));
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static int GetDeviceCapability(BinaryEmulator Instance, int Index)
        {
            int Dpi = (int)Win32kDpi.GetEffectiveDpi(Instance);

            switch (Index)
            {
                case HORZSIZE:
                    return Win32kDpi.GetScreenWidth(Instance) * TenthsOfMillimetrePerInch / (Dpi * 10);
                case VERTSIZE:
                    return Win32kDpi.GetScreenHeight(Instance) * TenthsOfMillimetrePerInch / (Dpi * 10);
                case HORZRES:
                    return Win32kDpi.GetScreenWidth(Instance);
                case VERTRES:
                    return Win32kDpi.GetScreenHeight(Instance);
                case LOGPIXELSX:
                case LOGPIXELSY:
                    return Dpi;
            }

            return Index switch
            {
                2 => 1, // TECHNOLOGY: DT_RASDISPLAY
                12 => 32, // BITSPIXEL
                14 => 1, // PLANES
                24 => -1, // NUMCOLORS
                116 => 60, // VREFRESH
                121 => 0x00000003, // COLORMGMTCAPS: CM_DEVICE_ICM | CM_GAMMA_RAMP
                _ => 0,
            };
        }
    }
}
