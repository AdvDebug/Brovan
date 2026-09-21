using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetWindowPlacement : IWinSyscall
    {
        private const int WindowPlacementSize = 44;
        private const uint SW_SHOWNORMAL = 1;
        private const uint SW_SHOWMINIMIZED = 2;
        private const uint SW_SHOWMAXIMIZED = 3;
        private const uint SW_HIDE = 0;

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

            Win32kHelper.GetAbsoluteWindowPosition(Instance, Window, out int Left, out int Top);
            int Right = Left + (int)Window.Width;
            int Bottom = Top + (int)Window.Height;

            uint ShowCommand = !Window.Visible ? SW_HIDE
                : Window.Minimized ? SW_SHOWMINIMIZED
                : Window.Maximized ? SW_SHOWMAXIMIZED
                : SW_SHOWNORMAL;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(WindowPlacementSize);
            Buffer.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), WindowPlacementSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x08, 4), ShowCommand);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x0C, 4), Left);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x10, 4), Top);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x14, 4), -1);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x18, 4), -1);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x1C, 4), Left);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x20, 4), Top);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x24, 4), Right);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x28, 4), Bottom);

            if (!Instance.WriteMemory(PlacementPtr, Buffer.Slice(0, WindowPlacementSize)))
            {
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
