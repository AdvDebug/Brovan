using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetTextExtent : IWinSyscall
    {
        private const int SizeStructSize = 8;
        private const int FallbackCharWidth = 8;
        private const int FallbackCharHeight = 16;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            Instance.WinHelper.GetArg(0);
            ulong StringPtr = Instance.WinHelper.GetArg(1);
            int Count = unchecked((int)Instance.WinHelper.GetArg(2));
            ulong SizePtr = Instance.WinHelper.GetArg(3);
            Instance.WinHelper.GetArg(4);

            if (SizePtr == 0 || !Instance.IsRegionMapped(SizePtr, SizeStructSize))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Count < 0)
            {
                Instance.SetLastWinError(87);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Cx = 0;
            int Cy = FallbackCharHeight;

            if (Count > 0 && StringPtr != 0)
            {
                int ByteCount = Count * 2;
                if (Instance.IsRegionMapped(StringPtr, (ulong)ByteCount))
                {
                    Span<byte> Raw = Instance.WinHelper.Shared.GetSpan((ulong)ByteCount);
                    if (Instance.ReadMemory(StringPtr, Raw.Slice(0, ByteCount), (uint)ByteCount))
                    {
                        char[] Chars = new char[Count];
                        for (int i = 0; i < Count; i++)
                            Chars[i] = (char)(Raw[i * 2] | (Raw[i * 2 + 1] << 8));
                        string Text = new string(Chars);

                        if (Instance.WinHelper.MeasureText(Text, out int MeasuredWidth, out int MeasuredHeight))
                        {
                            Cx = MeasuredWidth;
                            Cy = MeasuredHeight > 0 ? MeasuredHeight : FallbackCharHeight;
                        }
                        else
                        {
                            Cx = Count * FallbackCharWidth;
                        }
                    }
                    else
                    {
                        Cx = Count * FallbackCharWidth;
                    }
                }
                else
                {
                    Cx = Count * FallbackCharWidth;
                }
            }
            else if (Count == 0)
            {
                if (Instance.WinHelper.MeasureText(string.Empty, out int _, out int MeasuredHeight) && MeasuredHeight > 0)
                    Cy = MeasuredHeight;
            }

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(SizeStructSize);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0, 4), Cx);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(4, 4), Cy);

            if (!Instance.WriteMemory(SizePtr, Buffer.Slice(0, SizeStructSize)))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
