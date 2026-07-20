using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiPolyPolyDraw : IWinSyscall
    {
        private const uint PolygonType = 1;
        private const uint PolylineType = 2;
        private const int PointSize = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong PointsPtr = Instance.WinHelper.GetArg(1);
            ulong CountsPtr = Instance.WinHelper.GetArg(2);
            uint FigureCount = (uint)Instance.WinHelper.GetArg(3);
            uint DrawType = (uint)Instance.WinHelper.GetArg(4);

            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd == 0 || PointsPtr == 0 || CountsPtr == 0 || FigureCount == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (DrawType != PolygonType && DrawType != PolylineType)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kPenBrush Pen = Win32kHelper.ResolvePenBrush(Instance, Instance.WinHelper.ReadDcSelectedPen(Hdc), true);
            Win32kPenBrush Brush = DrawType == PolygonType
                ? Win32kHelper.ResolvePenBrush(Instance, Instance.WinHelper.ReadDcSelectedBrush(Hdc), false)
                : default;

            GdiPrimitiveKind Kind = DrawType == PolygonType ? GdiPrimitiveKind.Polygon : GdiPrimitiveKind.Polyline;

            ulong PointOffset = 0;
            for (uint Figure = 0; Figure < FigureCount; Figure++)
            {
                if (!Instance.IsRegionMapped(CountsPtr + (ulong)Figure * 4, 4))
                    break;

                uint PointCount = Instance.ReadMemoryUInt(CountsPtr + (ulong)Figure * 4);
                if (PointCount < 2)
                {
                    continue;
                }

                ulong FigureBytes = (ulong)PointCount * PointSize;
                ulong FigureAddr = PointsPtr + PointOffset;
                if (!Instance.IsRegionMapped(FigureAddr, FigureBytes))
                    break;

                GdiPoint[] Points = new GdiPoint[PointCount];
                for (uint i = 0; i < PointCount; i++)
                {
                    ulong Addr = FigureAddr + (ulong)i * PointSize;
                    Points[i] = new GdiPoint
                    {
                        X = unchecked((int)Instance.ReadMemoryUInt(Addr + 0x00)),
                        Y = unchecked((int)Instance.ReadMemoryUInt(Addr + 0x04)),
                    };
                }

                Instance.WinHelper.EnqueueGdiPoly(Hwnd, Kind, Points, Pen.ColorRef, Pen.PenWidth, Brush.ColorRef, DrawType == PolygonType);

                PointOffset += FigureBytes;
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
