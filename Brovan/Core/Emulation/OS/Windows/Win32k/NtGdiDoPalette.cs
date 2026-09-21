using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDoPalette : IWinSyscall
    {
        private const uint PaletteGetEntries = 2;
        private const uint PaletteGetSystemEntries = 3;
        private const uint PaletteGetColorTable = 5;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ushort Start = (ushort)Instance.WinHelper.GetArg(1);
            ushort Entries = (ushort)Instance.WinHelper.GetArg(2);
            ulong EntriesPtr = Instance.WinHelper.GetArg(3);
            uint Function = (uint)Instance.WinHelper.GetArg(4);
            _ = Start;

            uint Bytes = (uint)Entries * 4;
            bool Reading = Function == PaletteGetEntries || Function == PaletteGetSystemEntries || Function == PaletteGetColorTable;

            // The display never runs a palette, so the colours an app reads back are the identity ones.
            if (Reading && EntriesPtr != 0 && Bytes != 0)
            {
                if (!Instance.IsRegionMapped(EntriesPtr, Bytes) || !Instance.WinHelper.WriteZeroMemory(EntriesPtr, Bytes))
                {
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;
                }
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Entries);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
