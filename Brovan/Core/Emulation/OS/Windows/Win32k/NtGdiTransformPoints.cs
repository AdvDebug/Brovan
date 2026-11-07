using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiTransformPoints : IWinSyscall
    {
        private const int DeviceToWorld = 0;
        private const int WorldToDeviceFix = 2;
        private const int PointSize = 8;
        private const int MaxPoints = (int)(Win32kHelper.MaxGdiBufferBytes / PointSize);

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong SourcePtr = Instance.WinHelper.GetArg(1);
            ulong DestinationPtr = Instance.WinHelper.GetArg(2);
            int Count = unchecked((int)Instance.WinHelper.GetArg32(3));
            int Mode = unchecked((int)Instance.WinHelper.GetArg32(4)) & 0x7FFFFFFF;

            if (Count <= 0)
            {
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Count > MaxPoints || !Win32kHelper.IsKnownDc(Instance, Hdc) || Mode > WorldToDeviceFix)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // NT allows the input and output arrays to overlap.
            using CallBuffer Points = new CallBuffer(Count * PointSize);
            bool Done = false;
            if (Instance.ReadMemory(SourcePtr, Points.Span))
            {
                Transform(Instance, Hdc, Mode, Points.Span);
                Done = Instance.WriteMemory(DestinationPtr, Points.Span);
            }

            Instance.SetRawSyscallReturn(Done ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void Transform(BinaryEmulator Instance, ulong Hdc, int Mode, Span<byte> Data)
        {
            Instance.WinHelper.ReadDcPageOrigin(Hdc, out int PageX, out int PageY);
            Win32kHelper.GetWorldFix(Instance, Hdc, out int FixX, out int FixY);

            int AddX = Mode == DeviceToWorld ? -PageX + ((8 - FixX) >> 4) : PageX + Win32kHelper.FixToPixel(FixX);
            int AddY = Mode == DeviceToWorld ? -PageY + ((8 - FixY) >> 4) : PageY + Win32kHelper.FixToPixel(FixY);
            for (int Offset = 0; Offset < Data.Length; Offset += PointSize)
            {
                Span<byte> Point = Data.Slice(Offset, PointSize);
                int X = BinaryPrimitives.ReadInt32LittleEndian(Point);
                int Y = BinaryPrimitives.ReadInt32LittleEndian(Point.Slice(4));
                if (Mode == WorldToDeviceFix)
                {
                    X = unchecked(((X + PageX) << 4) + FixX);
                    Y = unchecked(((Y + PageY) << 4) + FixY);
                }
                else
                {
                    X = unchecked(X + AddX);
                    Y = unchecked(Y + AddY);
                }

                BinaryPrimitives.WriteInt32LittleEndian(Point, X);
                BinaryPrimitives.WriteInt32LittleEndian(Point.Slice(4), Y);
            }
        }
    }
}
