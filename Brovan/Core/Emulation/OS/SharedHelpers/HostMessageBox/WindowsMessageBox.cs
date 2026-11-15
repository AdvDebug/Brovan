using System;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    internal sealed class WindowsMessageBox : IHostMessageBox
    {
        private const int UoiFlags = 1;
        private const uint WsfVisible = 1;

        public int Show(HostMessageBoxRequest Request)
        {
            if (!HasVisibleWindowStation())
                return 0;

            return NativeWinImports.MessageBoxW(IntPtr.Zero, Request.Text, Request.Caption, Request.Style);
        }

        // A service session has no visible window station, and a box there waits for nobody.
        private static unsafe bool HasVisibleWindowStation()
        {
            IntPtr Station = NativeWinImports.GetProcessWindowStation();
            if (Station == IntPtr.Zero)
                return false;

            uint* Flags = stackalloc uint[3];
            return NativeWinImports.GetUserObjectInformationW(Station, UoiFlags, Flags, 12, out _) && (Flags[2] & WsfVisible) != 0;
        }
    }
}
