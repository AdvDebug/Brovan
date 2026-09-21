using System;
using System.Buffers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiSetDIBitsToDeviceInternal : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int DestX = unchecked((int)Instance.WinHelper.GetArg(1));
            int DestY = unchecked((int)Instance.WinHelper.GetArg(2));
            int Width = unchecked((int)Instance.WinHelper.GetArg(3));
            int Height = unchecked((int)Instance.WinHelper.GetArg(4));
            int SourceX = unchecked((int)Instance.WinHelper.GetArg(5));
            int SourceY = unchecked((int)Instance.WinHelper.GetArg(6));
            uint StartScan = (uint)Instance.WinHelper.GetArg(7);
            uint Scans = (uint)Instance.WinHelper.GetArg(8);
            ulong BitsAddress = Instance.WinHelper.GetArg(9);
            ulong HeaderAddress = Instance.WinHelper.GetArg(10);

            if (Width <= 0 || Height <= 0
                || !Win32kHelper.TryReadDibHeader(Instance, HeaderAddress, out Win32kHelper.DibHeader Header))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            _ = StartScan;
            _ = Scans;

            int Count = Width * Height;
            uint[] Pixels = ArrayPool<uint>.Shared.Rent(Count);
            bool Rendered;
            try
            {
                Span<uint> Block = Pixels.AsSpan(0, Count);
                Rendered = Win32kHelper.TryReadDibBlock(Instance, BitsAddress, Header, SourceX, SourceY, Width, Height, Block)
                    && Win32kHelper.BlitBlockToDc(Instance, Hdc, DestX, DestY, Width, Height, Block, Width, Height, Win32kHelper.SrcCopyRop);
            }
            finally
            {
                ArrayPool<uint>.Shared.Return(Pixels);
            }

            Instance.SetLastWinError(Rendered ? Win32kHelper.ERROR_SUCCESS : Win32kHelper.ERROR_INVALID_PARAMETER);
            Instance.SetRawSyscallReturn(Rendered ? (ulong)(uint)Height : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
