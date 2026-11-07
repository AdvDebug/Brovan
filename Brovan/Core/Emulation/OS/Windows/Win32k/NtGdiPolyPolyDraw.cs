using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiPolyPolyDraw : IWinSyscall
    {
        private const uint PolygonType = 1;
        private const uint PolylineType = 2;
        private const int PointSize = 8;
        private const uint MaxFigures = Win32kHelper.MaxGdiBufferBytes / sizeof(uint);
        private const ulong MaxPoints = Win32kHelper.MaxGdiBufferBytes / PointSize;

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

            if (FigureCount > MaxFigures)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.IsAccessible(CountsPtr, (ulong)FigureCount * 4, false))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> CountBytes = stackalloc byte[4];
            ulong TotalPoints = 0;
            for (uint Figure = 0; Figure < FigureCount && TotalPoints <= MaxPoints; Figure++)
            {
                if (!Instance.ReadMemory(CountsPtr + (ulong)Figure * 4, CountBytes))
                    TotalPoints = MaxPoints + 1;
                else
                    TotalPoints += BinaryPrimitives.ReadUInt32LittleEndian(CountBytes);
            }

            if (TotalPoints > MaxPoints || !Instance.IsAccessible(PointsPtr, TotalPoints * PointSize, false))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kPenBrush Pen = Win32kHelper.ResolveDcPenBrush(Instance, Hdc, Instance.WinHelper.ReadDcSelectedPen(Hdc), true);
            Win32kPenBrush Brush = DrawType == PolygonType
                ? Win32kHelper.ResolveDcPenBrush(Instance, Hdc, Instance.WinHelper.ReadDcSelectedBrush(Hdc), false)
                : default;

            GdiPrimitiveKind Kind = DrawType == PolygonType ? GdiPrimitiveKind.Polygon : GdiPrimitiveKind.Polyline;

            ulong PointOffset = 0;
            ulong PointsLeft = TotalPoints;

            for (uint Figure = 0; Figure < FigureCount; Figure++)
            {
                if (!Instance.ReadMemory(CountsPtr + (ulong)Figure * 4, CountBytes))
                    break;

                uint PointCount = BinaryPrimitives.ReadUInt32LittleEndian(CountBytes);
                if (PointCount > PointsLeft)
                    break;

                PointsLeft -= PointCount;
                ulong FigureBytes = (ulong)PointCount * PointSize;

                // A figure too short to draw still owns its points, and the ones after it are found past them.
                if (PointCount < 2)
                {
                    PointOffset += FigureBytes;
                    continue;
                }

                GdiPoint[] Points = new GdiPoint[PointCount];
                if (!Instance.ReadMemory(PointsPtr + PointOffset, MemoryMarshal.AsBytes(Points.AsSpan())))
                    break;

                Instance.WinHelper.EnqueueGdiPoly(Hwnd, Hdc, Kind, Points, Pen.ColorRef, Pen.PenWidth, Brush.ColorRef,
                    HasPen: !Pen.IsNull, HasBrush: DrawType == PolygonType && !Brush.IsNull);

                PointOffset += FigureBytes;
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
