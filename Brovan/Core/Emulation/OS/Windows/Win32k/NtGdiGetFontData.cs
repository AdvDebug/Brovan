using Brovan.Core.Emulation.OS.SharedHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetFontData : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            uint Table = (uint)Instance.WinHelper.GetArg(1);
            uint Offset = (uint)Instance.WinHelper.GetArg(2);
            ulong Buffer = Instance.WinHelper.GetArg(3);
            uint Size = (uint)Instance.WinHelper.GetArg(4);

            Instance.SetRawSyscallReturn(Read(Instance, Hdc, Table, Offset, Buffer, Size));
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static uint Read(BinaryEmulator Instance, ulong Hdc, uint Table, uint Offset, ulong Buffer, uint Size)
        {
            if (Size > Win32kHelper.MaxGdiBufferBytes)
                return Win32kHelper.GdiError;

            if (!Win32kHelper.IsKnownDc(Instance, Hdc))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_HANDLE);
                return Win32kHelper.GdiError;
            }

            if (!Win32kHelper.TryGetRealizedFont(Instance, Hdc, out ITextMetricsSupport Text, out IntPtr Font))
                return Win32kHelper.GdiError;

            if (Size == 0)
                return Text.GetFontData(Font, Table, Offset, Span<byte>.Empty);

            uint Done = 0;
            while (Done < Size && (ulong)Offset + Done <= uint.MaxValue)
            {
                int Chunk = (int)Math.Min(Size - Done, (uint)NtReadFile.IoChunkBytes);
                Span<byte> Data = Instance.WinHelper.Shared.GetSpan((ulong)Chunk).Slice(0, Chunk);
                uint Read = Text.GetFontData(Font, Table, Offset + Done, Data);
                if (Read == ITextMetricsSupport.NoFontData || Read > (uint)Chunk)
                    return Done == 0 ? Win32kHelper.GdiError : Done;

                if (!Instance.WriteMemory(Buffer + Done, Data.Slice(0, (int)Read)))
                    return Win32kHelper.GdiError;

                Done += Read;
                if (Read < (uint)Chunk)
                    break;
            }

            return Done;
        }
    }
}
