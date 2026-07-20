using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetEntry : IWinSyscall
    {
        private const int GdiEntrySize = 0x18;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Handle = Instance.WinHelper.GetArg(0);
            ulong OutBuffer = Instance.WinHelper.GetArg(1);

            if (OutBuffer == 0 || Handle == 0)
            {
                Instance.SetRawSyscallReturn(unchecked((ulong)(long)-1));
                return NTSTATUS.STATUS_SUCCESS;
            }

            ushort Index = (ushort)(Handle & 0xFFFF);
            const uint EntryCount = 0x1000;
            if (Index == 0 || Index >= EntryCount)
            {
                Instance.SetRawSyscallReturn(unchecked((ulong)(long)-1));
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong TableAddress = Instance.WinHelper.GetGdiHandleTableAddress();
            if (TableAddress == 0)
            {
                Instance.SetRawSyscallReturn(unchecked((ulong)(long)-1));
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Entry = TableAddress + (ulong)Index * GdiEntrySize;
            if (!Instance.IsRegionMapped(Entry, GdiEntrySize) || !Instance.IsRegionMapped(OutBuffer, GdiEntrySize))
            {
                Instance.SetRawSyscallReturn(unchecked((ulong)(long)-1));
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(GdiEntrySize);
            if (!Instance.ReadMemory(Entry, Buffer.Slice(0, GdiEntrySize), (uint)GdiEntrySize))
            {
                Instance.SetRawSyscallReturn(unchecked((ulong)(long)-1));
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.WriteMemory(OutBuffer, Buffer.Slice(0, GdiEntrySize)))
            {
                Instance.SetRawSyscallReturn(unchecked((ulong)(long)-1));
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
