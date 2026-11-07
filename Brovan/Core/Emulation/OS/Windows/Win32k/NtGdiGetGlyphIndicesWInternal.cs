using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetGlyphIndicesWInternal : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong TextPtr = Instance.WinHelper.GetArg(1);
            int Count = (int)Instance.WinHelper.GetArg32(2);
            ulong IndicesPtr = Instance.WinHelper.GetArg(3);
            uint Mode = (uint)Instance.WinHelper.GetArg(4);
            bool Subset = (uint)Instance.WinHelper.GetArg(5) != 0;

            Instance.SetRawSyscallReturn(Win32kHelper.GetGlyphIndices(Instance, Hdc, TextPtr, Count, IndicesPtr, Mode, Subset));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
