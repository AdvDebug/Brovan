using System.Buffers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserUpdateLayeredWindow : IWinSyscall
    {
        private const uint SrcCopy = 0x00CC0020;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong DestPointPtr = Instance.WinHelper.GetArg(2);
            ulong SizePtr = Instance.WinHelper.GetArg(3);
            ulong SourceDc = Instance.WinHelper.GetArg(4);
            ulong SourcePointPtr = Instance.WinHelper.GetArg(5);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Width = (int)Window.Width;
            int Height = (int)Window.Height;

            if (SizePtr != 0 && TryReadPair(Instance, SizePtr, out int NewWidth, out int NewHeight))
            {
                Width = NewWidth;
                Height = NewHeight;
            }

            int DestX = Window.X;
            int DestY = Window.Y;
            bool Moved = DestPointPtr != 0 && TryReadPair(Instance, DestPointPtr, out DestX, out DestY);

            uint Flags = Win32kHelper.SwpNoZOrder | Win32kHelper.SwpNoActivate | (Moved ? 0u : Win32kHelper.SwpNoMove);
            Win32kHelper.ApplyWindowPos(Instance, new Win32kHelper.Win32kDeferredWindowPos
            {
                Hwnd = Hwnd,
                X = DestX,
                Y = DestY,
                Width = Width,
                Height = Height,
                Flags = Flags,
            });

            int SourceX = 0;
            int SourceY = 0;
            if (SourcePointPtr != 0)
                TryReadPair(Instance, SourcePointPtr, out SourceX, out SourceY);

            // The layered surface is the whole window.
            if (SourceDc != 0 && Win32kHelper.IsBlitExtentValid(Width, Height))
            {
                int Count = Width * Height;
                uint[] Pixels = ArrayPool<uint>.Shared.Rent(Count);
                try
                {
                    Span<uint> Block = Pixels.AsSpan(0, Count);
                    if (Win32kHelper.TryReadDcBlock(Instance, SourceDc, SourceX, SourceY, Width, Height, Block))
                        Win32kHelper.BlitBlockToWindow(Instance, Hwnd, 0, 0, Width, Height, Block, Width, Height, SrcCopy);
                }
                finally
                {
                    ArrayPool<uint>.Shared.Return(Pixels);
                }
            }

            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryReadPair(BinaryEmulator Instance, ulong Address, out int First, out int Second)
        {
            First = 0;
            Second = 0;

            if (!Instance.IsRegionMapped(Address, 8))
                return false;

            First = unchecked((int)Instance.ReadMemoryUInt(Address));
            Second = unchecked((int)Instance.ReadMemoryUInt(Address + 4));
            return true;
        }
    }
}
