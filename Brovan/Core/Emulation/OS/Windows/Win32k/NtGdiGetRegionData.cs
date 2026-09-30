using System.Buffers.Binary;
using System.Collections.Generic;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetRegionData : IWinSyscall
    {
        private const int HeaderSize = 32;
        private const uint RdhRectangles = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Region = Instance.WinHelper.GetArg(0);
            uint Count = (uint)Instance.WinHelper.GetArg(1);
            ulong DataPtr = Instance.WinHelper.GetArg(2);

            Win32kHelper.GetRegionScratch(Instance, out List<GdiClipRect> Rects, out _, out _);
            if (!Win32kHelper.TryReadRegion(Instance, Region, Rects))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_HANDLE);

            uint Needed = (uint)(HeaderSize + Rects.Count * Win32kHelper.GuestRectSize);
            if (DataPtr == 0)
            {
                Instance.SetRawSyscallReturn(Needed);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Count < Needed)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            Win32kHelper.GetRegionBounds(Rects, out GdiClipRect Bounds);
            Span<byte> Span = Instance.WinHelper.Shared.GetSpan((ulong)Needed).Slice(0, (int)Needed);
            BinaryPrimitives.WriteUInt32LittleEndian(Span, HeaderSize);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(4), RdhRectangles);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(8), (uint)Rects.Count);
            BinaryPrimitives.WriteUInt32LittleEndian(Span.Slice(12), (uint)(Rects.Count * Win32kHelper.GuestRectSize));
            Win32kHelper.WriteGuestRect(Span.Slice(16), Bounds);
            for (int i = 0; i < Rects.Count; i++)
                Win32kHelper.WriteGuestRect(Span.Slice(HeaderSize + i * Win32kHelper.GuestRectSize), Rects[i]);

            if (!Instance.WriteMemory(DataPtr, Span))
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            Instance.SetRawSyscallReturn(Needed);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
