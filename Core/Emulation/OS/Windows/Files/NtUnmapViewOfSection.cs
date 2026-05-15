using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtUnmapViewOfSection : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                ulong BaseAddress = Instance.WinHelper.GetArg64(1);
                return NtUnmapViewOfSectionEx.UnmapView(Instance, ProcessHandle, BaseAddress, 0, nameof(NtUnmapViewOfSection));
            }
            else
            {
                uint ProcessHandle = Instance.WinHelper.GetArg32(0);
                uint BaseAddress = Instance.WinHelper.GetArg32(1);
                return NtUnmapViewOfSectionEx.UnmapView(Instance, ProcessHandle, BaseAddress, 0, nameof(NtUnmapViewOfSection));
            }
        }
    }
}