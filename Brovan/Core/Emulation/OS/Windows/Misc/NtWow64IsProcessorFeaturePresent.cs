namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWow64IsProcessorFeaturePresent : IWinSyscall
    {
        private const uint ProcessorFeaturesOffset = 0x274;
        private const uint ProcessorFeatureCount = 64;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Feature = (uint)Instance.WinHelper.GetArg(0);
            uint Present = 0;

            if (Feature < ProcessorFeatureCount)
                Present = Instance._emulator.ReadMemoryUInt(Instance.KUSER_SHARED_DATA + ProcessorFeaturesOffset + Feature) & 0xFF;

            Instance.SetRawSyscallReturn(Present);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
