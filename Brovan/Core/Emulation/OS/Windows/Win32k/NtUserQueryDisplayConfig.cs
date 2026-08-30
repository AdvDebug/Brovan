namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserQueryDisplayConfig : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PathCountPtr = Instance.WinHelper.GetArg(1);
            ulong PathArrayPtr = Instance.WinHelper.GetArg(2);
            ulong ModeCountPtr = Instance.WinHelper.GetArg(3);
            ulong ModeArrayPtr = Instance.WinHelper.GetArg(4);
            ulong TopologyPtr = Instance.WinHelper.GetArg(5);

            if (PathCountPtr == 0 || PathArrayPtr == 0)
                return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            if (!Instance.IsRegionMapped(PathCountPtr, 4))
                return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            if (Instance.ReadMemoryUInt(PathCountPtr) < Win32kDisplayConfig.PathCount)
                return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_INSUFFICIENT_BUFFER);

            if (!Instance.IsRegionMapped(PathArrayPtr, Win32kDisplayConfig.PathInfoSize))
                return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            // A caller after the topology only asks for paths and leaves the mode array out.
            bool WantsModes = ModeCountPtr != 0 && ModeArrayPtr != 0;

            if (WantsModes)
            {
                if (!Instance.IsRegionMapped(ModeCountPtr, 4))
                    return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

                if (Instance.ReadMemoryUInt(ModeCountPtr) < Win32kDisplayConfig.ModeCount)
                    return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_INSUFFICIENT_BUFFER);

                if (!Instance.IsRegionMapped(ModeArrayPtr, Win32kDisplayConfig.ModeInfoSize * Win32kDisplayConfig.ModeCount))
                    return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);
            }

            if (!Win32kDisplayConfig.WritePaths(Instance, PathArrayPtr))
                return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            if (WantsModes)
            {
                if (!Win32kDisplayConfig.WriteModes(Instance, ModeArrayPtr))
                    return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

                Instance._emulator.WriteMemory(ModeCountPtr, Win32kDisplayConfig.ModeCount, 4);
            }

            Instance._emulator.WriteMemory(PathCountPtr, Win32kDisplayConfig.PathCount, 4);

            if (TopologyPtr != 0 && Instance.IsRegionMapped(TopologyPtr, 4))
                Instance._emulator.WriteMemory(TopologyPtr, Win32kDisplayConfig.TopologyInternal, 4);

            return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_SUCCESS);
        }
    }
}
