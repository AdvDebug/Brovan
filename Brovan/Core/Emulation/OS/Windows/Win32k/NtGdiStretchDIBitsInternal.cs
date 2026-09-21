using System;
using System.Buffers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiStretchDIBitsInternal : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int DestX = unchecked((int)Instance.WinHelper.GetArg(1));
            int DestY = unchecked((int)Instance.WinHelper.GetArg(2));
            int DestWidth = unchecked((int)Instance.WinHelper.GetArg(3));
            int DestHeight = unchecked((int)Instance.WinHelper.GetArg(4));
            int SourceX = unchecked((int)Instance.WinHelper.GetArg(5));
            int SourceY = unchecked((int)Instance.WinHelper.GetArg(6));
            int SourceWidth = unchecked((int)Instance.WinHelper.GetArg(7));
            int SourceHeight = unchecked((int)Instance.WinHelper.GetArg(8));
            ulong BitsAddress = Instance.WinHelper.GetArg(9);
            ulong HeaderAddress = Instance.WinHelper.GetArg(10);
            uint Rop = (uint)Instance.WinHelper.GetArg(12);

            if (DestWidth <= 0 || DestHeight <= 0 || SourceWidth <= 0 || SourceHeight <= 0
                || !Win32kHelper.TryReadDibHeader(Instance, HeaderAddress, out Win32kHelper.DibHeader Header))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Count = SourceWidth * SourceHeight;
            uint[] Pixels = ArrayPool<uint>.Shared.Rent(Count);
            bool Rendered;
            try
            {
                Span<uint> Block = Pixels.AsSpan(0, Count);
                Rendered = Win32kHelper.TryReadDibBlock(Instance, BitsAddress, Header, SourceX, SourceY, SourceWidth, SourceHeight, Block)
                    && Win32kHelper.BlitBlockToDc(Instance, Hdc, DestX, DestY, DestWidth, DestHeight, Block, SourceWidth, SourceHeight, Rop);
            }
            finally
            {
                ArrayPool<uint>.Shared.Return(Pixels);
            }

            Instance.SetLastWinError(Rendered ? Win32kHelper.ERROR_SUCCESS : Win32kHelper.ERROR_INVALID_PARAMETER);
            Instance.SetRawSyscallReturn(Rendered ? (ulong)(uint)SourceHeight : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
