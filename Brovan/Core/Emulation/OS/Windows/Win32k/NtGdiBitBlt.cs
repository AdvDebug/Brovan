using System;
using System.Buffers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiBitBlt : IWinSyscall
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
            uint Rop = (uint)Instance.WinHelper.GetArg(8);

            if (Width <= 0 || Height <= 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Count = Width * Height;
            uint[] Pixels = ArrayPool<uint>.Shared.Rent(Count);
            bool Rendered;
            try
            {
                Span<uint> Block = Pixels.AsSpan(0, Count);
                if (!Win32kHelper.TryReadDcBlock(Instance, SourceDc, SourceX, SourceY, Width, Height, Block))
                {
                    // A rop with no source term draws from the pattern alone.
                    if (Win32kHelper.RopUsesSource(Rop))
                    {
                        Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                        Instance.SetRawSyscallReturn(0);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                    Block.Clear();
                }

                Rendered = Win32kHelper.BlitBlockToDc(Instance, DestDc, X, Y, Width, Height, Block, Width, Height, Rop);
            }
            finally
            {
                ArrayPool<uint>.Shared.Return(Pixels);
            }

            Instance.SetLastWinError(Rendered ? Win32kHelper.ERROR_SUCCESS : Win32kHelper.ERROR_INVALID_HANDLE);
            Instance.SetRawSyscallReturn(Rendered ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
