using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreateRectRgn : IWinSyscall
    {
        private const byte RegionHandleType = 0x04;
        private const int RegionObjectSize = 0x30;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            int X1 = unchecked((int)Instance.WinHelper.GetArg(0));
            int Y1 = unchecked((int)Instance.WinHelper.GetArg(1));
            int X2 = unchecked((int)Instance.WinHelper.GetArg(2));
            int Y2 = unchecked((int)Instance.WinHelper.GetArg(3));

            int Left = System.Math.Min(X1, X2);
            int Right = System.Math.Max(X1, X2);
            int Top = System.Math.Min(Y1, Y2);
            int Bottom = System.Math.Max(Y1, Y2);

            ulong Handle = Instance.WinHelper.AllocateGdiHandle(RegionHandleType);
            if (Handle == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong RegionObject = Instance.MapUniqueAddress((ulong)RegionObjectSize, MemoryProtection.ReadWrite);
            if (RegionObject != 0)
            {
                Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(RegionObjectSize);
                Buffer.Clear();

                int IType = (Left == Right || Top == Bottom) ? 1 : 2;
                WriteI32(Buffer, 0x00, RegionObjectSize);
                WriteI32(Buffer, 0x04, IType);
                WriteI32(Buffer, 0x08, Left);
                WriteI32(Buffer, 0x0C, Top);
                WriteI32(Buffer, 0x10, Right);
                WriteI32(Buffer, 0x14, Bottom);

                if (!Instance.WriteMemory(RegionObject, Buffer.Slice(0, RegionObjectSize)))
                {
                    RegionObject = 0;
                }
                else
                {
                    Instance.WinHelper.AttachGdiKernelObject(Handle, RegionObject);
                }
            }

            Instance.SetRawSyscallReturn(Handle);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void WriteI32(Span<byte> Buffer, int Offset, int Value)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(Offset, 4), Value);
        }
    }
}
