using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserQueryDisplayConfig : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PathCountPtr = Instance.WinHelper.GetArg(1);
            ulong ModalityPtr = Instance.WinHelper.GetArg(2);
            ulong TopologyPtr = Instance.WinHelper.GetArg(3);

            if (PathCountPtr == 0 || !Instance.IsRegionMapped(PathCountPtr, 4))
                return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);

            if (Instance.ReadMemoryUInt(PathCountPtr) < Win32kDisplayConfig.PathCount)
                return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_BUFFER_TOO_SMALL);

            if (ModalityPtr == 0 || !Instance.IsRegionMapped(ModalityPtr, Win32kDisplayConfig.ModalitySize))
                return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);

            if (!Win32kDisplayConfig.WriteModality(Instance, ModalityPtr))
                return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);

            Instance._emulator.WriteMemory(PathCountPtr, Win32kDisplayConfig.PathCount, 4);

            if (TopologyPtr != 0 && Instance.IsRegionMapped(TopologyPtr, 4))
                Instance._emulator.WriteMemory(TopologyPtr, Win32kDisplayConfig.TopologyInternal, 4);

            return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_SUCCESS);
        }
    }
}
