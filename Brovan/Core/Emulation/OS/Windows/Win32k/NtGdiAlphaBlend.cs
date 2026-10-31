using System;
using System.Buffers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiAlphaBlend : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DestDc = Instance.WinHelper.GetArg(0);
            int X = unchecked((int)Instance.WinHelper.GetArg(1));
            int Y = unchecked((int)Instance.WinHelper.GetArg(2));
            int Width = unchecked((int)Instance.WinHelper.GetArg(3));
            int Height = unchecked((int)Instance.WinHelper.GetArg(4));
            ulong SourceDc = Instance.WinHelper.GetArg(5);
            int SourceX = unchecked((int)Instance.WinHelper.GetArg(6));
            int SourceY = unchecked((int)Instance.WinHelper.GetArg(7));
            int SourceWidth = unchecked((int)Instance.WinHelper.GetArg(8));
            int SourceHeight = unchecked((int)Instance.WinHelper.GetArg(9));
            uint Function = (uint)Instance.WinHelper.GetArg(10);

            byte Operation = (byte)Function;
            byte Format = (byte)(Function >> 24);
            if (Operation != Win32kHelper.BlendOpSourceOver || (Format & ~Win32kHelper.AlphaFormatSourceAlpha) != 0
                || Width < 0 || Height < 0 || SourceWidth < 0 || SourceHeight < 0)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            // A null source DC leaves LastError unchanged.
            if (SourceDc == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Width == 0 || Height == 0 || SourceWidth == 0 || SourceHeight == 0)
            {
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.IsBlitExtentValid(Width, Height) || !Win32kHelper.IsBlitExtentValid(SourceWidth, SourceHeight))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            if (!Win32kHelper.TryGetDcBitmap(Instance, SourceDc, out Win32kBitmap Source))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_HANDLE);

            Instance.WinHelper.ReadDcOrigin(SourceDc, out int SourceOffsetX, out int SourceOffsetY);
            long Left = (long)SourceX + SourceOffsetX;
            long Top = (long)SourceY + SourceOffsetY;
            if (Left < 0 || Top < 0 || Left + SourceWidth > Source.Width || Top + SourceHeight > Source.Height)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            int Count = SourceWidth * SourceHeight;
            uint[] Pixels = Win32kHelper.RentGuiPixels(Count, out bool Pooled);
            bool Rendered;
            try
            {
                Span<uint> Block = Pixels.AsSpan(0, Count);
                if (!Win32kHelper.TryReadBitmapBlock(Instance, Source, (int)Left, (int)Top, SourceWidth, SourceHeight, Block))
                    return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_HANDLE);

                Rendered = Win32kHelper.BlitBlockToDc(Instance, DestDc, X, Y, Width, Height, Block, SourceWidth, SourceHeight, Win32kHelper.SrcCopyRop, Function);
            }
            finally
            {
                if (Pooled)
                    ArrayPool<uint>.Shared.Return(Pixels);
            }

            Instance.SetRawSyscallReturn(Rendered ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
