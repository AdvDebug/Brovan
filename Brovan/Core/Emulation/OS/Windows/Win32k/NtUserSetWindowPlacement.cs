using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetWindowPlacement : IWinSyscall
    {
        private const int WindowPlacementSize = 44;
        private const uint SwpNoZOrder = 0x0004;
        private const uint SwpShowWindow = 0x0040;
        private const uint SwpHideWindow = 0x0080;

        private const uint SwHide = 0;
        private const uint SwShowMinimized = 2;
        private const uint SwShowMaximized = 3;
        private const uint SwShowMinNoActive = 7;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong PlacementPtr = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null || PlacementPtr == 0 || !Instance.IsRegionMapped(PlacementPtr, WindowPlacementSize))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(WindowPlacementSize).Slice(0, WindowPlacementSize);
            if (!Instance.ReadMemory(PlacementPtr, Buffer))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint ShowCommand = BinaryPrimitives.ReadUInt32LittleEndian(Buffer.Slice(0x08, 4));
            int Left = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x1C, 4));
            int Top = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x20, 4));
            int Right = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x24, 4));
            int Bottom = BinaryPrimitives.ReadInt32LittleEndian(Buffer.Slice(0x28, 4));

            Window.Minimized = ShowCommand == SwShowMinimized || ShowCommand == SwShowMinNoActive;
            Window.Maximized = ShowCommand == SwShowMaximized;

            uint Flags = SwpNoZOrder | (ShowCommand == SwHide ? SwpHideWindow : SwpShowWindow);

            Win32kHelper.ApplyWindowPos(Instance, new Win32kHelper.Win32kDeferredWindowPos
            {
                Hwnd = Hwnd,
                X = Left,
                Y = Top,
                Width = Right - Left,
                Height = Bottom - Top,
                Flags = Flags,
            });

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
