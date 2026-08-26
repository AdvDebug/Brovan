using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetScrollInfo : IWinSyscall
    {
        private const int SbHorizontal = 0;
        private const int SbVertical = 1;

        private const uint SifRange = 0x0001;
        private const uint SifPage = 0x0002;
        private const uint SifPos = 0x0004;
        private const uint SifTrackPos = 0x0010;
        private const int ScrollInfoSize = 28;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            int Bar = unchecked((int)Instance.WinHelper.GetArg(1));
            ulong InfoPtr = Instance.WinHelper.GetArg(2);
            bool Redraw = Instance.WinHelper.GetArg(3) != 0;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null || (Bar != SbHorizontal && Bar != SbVertical) || InfoPtr == 0)
            {
                Instance.SetLastWinError(Window == null
                    ? Win32kHelper.ERROR_INVALID_WINDOW_HANDLE
                    : Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Raw = stackalloc byte[ScrollInfoSize];
            if (!Instance.ReadMemory(InfoPtr, Raw, ScrollInfoSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Mask = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(4, 4));
            WinScrollBarInfo Info = Bar == SbHorizontal ? Window.HorizontalScroll : Window.VerticalScroll;

            if ((Mask & SifRange) != 0)
            {
                Info.Minimum = BinaryPrimitives.ReadInt32LittleEndian(Raw.Slice(8, 4));
                Info.Maximum = BinaryPrimitives.ReadInt32LittleEndian(Raw.Slice(12, 4));
                if (Info.Maximum < Info.Minimum)
                    Info.Maximum = Info.Minimum;
            }

            if ((Mask & SifPage) != 0)
                Info.Page = BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(16, 4));

            if ((Mask & SifPos) != 0)
                Info.Position = BinaryPrimitives.ReadInt32LittleEndian(Raw.Slice(20, 4));

            if ((Mask & SifTrackPos) != 0)
                Info.TrackPosition = BinaryPrimitives.ReadInt32LittleEndian(Raw.Slice(24, 4));

            // The thumb stops where the page starts. The range is the guest's, so this is done wide.
            long Highest = Info.Page > 1 ? (long)Info.Maximum - (Info.Page - 1) : Info.Maximum;
            if (Highest < Info.Minimum)
                Highest = Info.Minimum;

            if (Info.Position < Info.Minimum)
                Info.Position = Info.Minimum;
            else if (Info.Position > Highest)
                Info.Position = (int)Highest;

            if (Bar == SbHorizontal)
                Window.HorizontalScroll = Info;
            else
                Window.VerticalScroll = Info;

            if (Redraw)
                Win32kHelper.InvalidateWindow(Instance, Hwnd);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(unchecked((ulong)(long)Info.Position));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
