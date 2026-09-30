using System.Buffers;
using System.Buffers.Binary;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserUpdateLayeredWindow : IWinSyscall
    {
        private const uint SrcCopy = 0x00CC0020;
        private const uint UlwExNoResize = 0x00000008;
        private const uint ValidFlags = 0x0000002F;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong DestPointPtr = Instance.WinHelper.GetArg(2);
            ulong SizePtr = Instance.WinHelper.GetArg(3);
            ulong SourceDc = Instance.WinHelper.GetArg(4);
            ulong SourcePointPtr = Instance.WinHelper.GetArg(5);
            uint ColorKey = (uint)Instance.WinHelper.GetArg(6);
            ulong BlendPtr = Instance.WinHelper.GetArg(7);
            uint Flags = (uint)Instance.WinHelper.GetArg(8);
            ulong DirtyPtr = Instance.WinHelper.GetArg(9);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            int Width = (int)Window.Width;
            int Height = (int)Window.Height;
            bool Sized = SizePtr != 0;
            if (Sized)
            {
                if (!TryReadPair(Instance, SizePtr, out Width, out Height))
                    return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

                if (Width < 0 || Height < 0)
                    return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);
            }

            int DestX = Window.X;
            int DestY = Window.Y;
            bool Moved = DestPointPtr != 0;
            if (Moved && !TryReadPair(Instance, DestPointPtr, out DestX, out DestY))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

            // NT: probed even without a source DC.
            int SourceX = 0;
            int SourceY = 0;
            if (SourcePointPtr != 0 && !TryReadPair(Instance, SourcePointPtr, out SourceX, out SourceY))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

            byte ConstantAlpha = 0xFF;
            byte AlphaFormat = 0;
            if (BlendPtr != 0)
            {
                Span<byte> Blend = stackalloc byte[4];
                if (!Instance.ReadMemory(BlendPtr, Blend))
                    return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

                ConstantAlpha = Blend[2];
                AlphaFormat = Blend[3];
            }

            GdiClipRect Dirty = new GdiClipRect { Right = Width, Bottom = Height };
            if (DirtyPtr != 0)
            {
                if (!Win32kHelper.TryReadGuestRect(Instance, DirtyPtr, out Dirty))
                    return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_NOACCESS);

                if (Dirty.Left < 0 || Dirty.Top < 0)
                    return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);
            }

            if ((Flags & ~ValidFlags) != 0)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            // NT: fails on a window layered by SetLayeredWindowAttributes.
            if ((Window.ExStyle & Win32kHelper.WindowExStyleLayered) == 0 || Window.LayeredByAttributes)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            if ((Flags & UlwExNoResize) != 0 && Sized && (Width != (int)Window.Width || Height != (int)Window.Height))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INCORRECT_SIZE);

            Window.X = DestX;
            Window.Y = DestY;
            Window.Width = (uint)Width;
            Window.Height = (uint)Height;
            Window.LayeredByUpdate = true;
            Instance.WinHelper.MaterializeUserWindow(Window);

            if (Instance.WinHelper.UsesTopLevelHost && Window.ParentHwnd == 0)
            {
                LayeredUpdate Update = new LayeredUpdate
                {
                    X = Window.X,
                    Y = Window.Y,
                    Width = (int)Window.Width,
                    Height = (int)Window.Height,
                    ColorKey = ColorKey,
                    ConstantAlpha = ConstantAlpha,
                    AlphaFormat = AlphaFormat,
                    Flags = Flags,
                };

                // A hidden window may have no host surface to keep the pixels a partial update leaves out.
                if (!Window.Visible)
                    Dirty = new GdiClipRect { Right = Update.Width, Bottom = Update.Height };

                int DirtyLeft = Math.Min(Dirty.Left, Update.Width);
                int DirtyTop = Math.Min(Dirty.Top, Update.Height);
                int DirtyWidth = Math.Clamp(Dirty.Right, DirtyLeft, Update.Width) - DirtyLeft;
                int DirtyHeight = Math.Clamp(Dirty.Bottom, DirtyTop, Update.Height) - DirtyTop;

                // The host surface is the whole window. Past the budget it moves and resizes with no pixels.
                if (SourceDc != 0 && DirtyWidth > 0 && DirtyHeight > 0 && Win32kHelper.IsBlitExtentValid(Update.Width, Update.Height))
                    ReadDirtyBlock(Instance, Update, SourceDc, SourceX + DirtyLeft, SourceY + DirtyTop, DirtyLeft, DirtyTop, DirtyWidth, DirtyHeight);

                Instance.WinHelper.EnqueueLayeredUpdate(Hwnd, Update);
            }
            else if (SourceDc != 0 && Win32kHelper.IsBlitExtentValid(Width, Height))
            {
                // A child window or a single surface host has no layered host window, so the surface is drawn opaque.
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

            Instance.WinHelper.PresentDesktop();

            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void ReadDirtyBlock(BinaryEmulator Instance, LayeredUpdate Update, ulong SourceDc, int SourceX, int SourceY,
            int Left, int Top, int Width, int Height)
        {
            int Count = Width * Height;
            uint[] Pixels = Win32kHelper.RentGuiPixels(Count, out bool Pooled);

            if (!Win32kHelper.TryReadDcBlock(Instance, SourceDc, SourceX, SourceY, Width, Height, Pixels.AsSpan(0, Count)))
            {
                if (Pooled)
                    ArrayPool<uint>.Shared.Return(Pixels);

                return;
            }

            Update.Pixels = Pixels;
            Update.PixelsPooled = Pooled;
            Update.DirtyLeft = Left;
            Update.DirtyTop = Top;
            Update.DirtyWidth = Width;
            Update.DirtyHeight = Height;
        }

        private static bool TryReadPair(BinaryEmulator Instance, ulong Address, out int First, out int Second)
        {
            First = 0;
            Second = 0;

            Span<byte> Pair = stackalloc byte[8];
            if (!Instance.ReadMemory(Address, Pair))
                return false;

            First = BinaryPrimitives.ReadInt32LittleEndian(Pair);
            Second = BinaryPrimitives.ReadInt32LittleEndian(Pair.Slice(4));
            return true;
        }
    }
}
