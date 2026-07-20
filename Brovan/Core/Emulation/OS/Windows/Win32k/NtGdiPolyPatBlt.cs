using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiPolyPatBlt : IWinSyscall
    {
        private const int EntrySize = 24;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hdc = Instance.WinHelper.GetArg(0);
            uint Rop = (uint)Instance.WinHelper.GetArg(1);
            ulong SrcPtr = Instance.WinHelper.GetArg(2);
            uint Count = (uint)Instance.WinHelper.GetArg(3);

            ulong Hwnd = Instance.WinHelper.GetHwndFromDc(Hdc);
            if (Hwnd == 0 || SrcPtr == 0 || Count == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            for (uint i = 0; i < Count; i++)
            {
                ulong EntryAddr = SrcPtr + (ulong)i * EntrySize;
                if (!Instance.IsRegionMapped(EntryAddr, EntrySize))
                    break;

                int X = unchecked((int)Instance.ReadMemoryUInt(EntryAddr + 0x00));
                int Y = unchecked((int)Instance.ReadMemoryUInt(EntryAddr + 0x04));
                int Width = unchecked((int)Instance.ReadMemoryUInt(EntryAddr + 0x08));
                int Height = unchecked((int)Instance.ReadMemoryUInt(EntryAddr + 0x0C));
                ulong BrushHandle = Instance.ReadMemoryULong(EntryAddr + 0x10);

                Win32kPenBrush Brush = Win32kHelper.ResolvePenBrush(Instance, BrushHandle, false);
                Instance.WinHelper.EnqueueGdiFillRect(Hwnd, X, Y, X + Width, Y + Height, Brush.ColorRef, Rop);
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
