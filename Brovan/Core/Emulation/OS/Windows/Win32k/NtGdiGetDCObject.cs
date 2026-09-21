using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetDCObject : IWinSyscall
    {
        // GetCurrentObject maps OBJ_* onto the GDI handle type before it reaches win32k.
        private const int BitmapType = 0x050000;
        private const int PaletteType = 0x080000;
        private const int ColorSpaceType = 0x090000;
        private const int FontType = 0x0A0000;
        private const int BrushType = 0x100000;
        private const int PenType = 0x300000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int ObjectType = unchecked((int)Instance.WinHelper.GetArg(1));

            ulong Object = ObjectType switch
            {
                PenType => Instance.WinHelper.ReadDcSelectedPen(Hdc),
                BrushType => Instance.WinHelper.ReadDcSelectedBrush(Hdc),
                FontType => Win32kHelper.GetDcSelectedFont(Instance, Hdc),
                BitmapType => Win32kHelper.GetDcSelectedBitmap(Instance, Hdc),
                PaletteType => Win32kHelper.GetDcSelectedPalette(Instance, Hdc),
                ColorSpaceType => 0,
                _ => 0,
            };

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Object);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
