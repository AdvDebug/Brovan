using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetCharWidthW : IWinSyscall
    {
        private const uint MaxEntries = Win32kHelper.MaxGdiBufferBytes / sizeof(uint);

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            uint First = (uint)Instance.WinHelper.GetArg(1);
            uint Count = (uint)Instance.WinHelper.GetArg(2);
            ulong CodesPtr = Instance.WinHelper.GetArg(3);
            uint Flags = (uint)Instance.WinHelper.GetArg(4);
            ulong BufferPtr = Instance.WinHelper.GetArg(5);

            bool Done = Count != 0 && Count <= MaxEntries
                && Win32kHelper.CopyCharWidths(Instance, Hdc, First, Count, CodesPtr, Flags, BufferPtr, false);

            Instance.SetBooleanSyscallReturn(Done);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
