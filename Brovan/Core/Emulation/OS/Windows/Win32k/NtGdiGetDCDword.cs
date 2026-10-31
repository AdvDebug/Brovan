using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetDCDword : IWinSyscall
    {
        private const uint IndexJournal = 0;
        private const uint IndexRelAbs = 1;
        private const uint IndexBreakExtra = 2;
        private const uint IndexBreakCount = 3;
        private const uint IndexArcDirection = 4;
        private const uint IndexSaveDepth = 5;
        private const uint IndexFontLanguageInfo = 6;
        private const uint IndexMemoryDc = 7;
        private const uint IndexMapMode = 8;

        private const uint NotJournaling = 1;
        private const uint RelAbsAbsolute = 1;
        private const uint ArcCounterClockwise = 1;
        private const uint GcpError = 0x8000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            uint Index = Instance.WinHelper.GetArg32(1);
            ulong ValuePtr = Instance.WinHelper.GetArg(2);

            ulong Attributes = Instance.WinHelper.GetDcAttributeAddress(Hdc);
            if (Attributes == 0 || !Win32kHelper.TryDescribeDc(Instance, Hdc, out bool MemoryDc, out int SaveDepth)
                || !TryGetValue(Instance, Index, Attributes, MemoryDc, SaveDepth, out uint Value))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(Instance.WinHelper.WriteUInt32(ValuePtr, Value) ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryGetValue(BinaryEmulator Instance, uint Index, ulong Attributes, bool MemoryDc, int SaveDepth, out uint Value)
        {
            switch (Index)
            {
                case IndexJournal:
                    Value = NotJournaling;
                    return true;

                case IndexRelAbs:
                    Value = RelAbsAbsolute;
                    return true;

                case IndexArcDirection:
                    Value = ArcCounterClockwise;
                    return true;

                case IndexBreakExtra:
                    return Instance.WinHelper.TryReadUInt32(Attributes + WinSysHelper.DcAttrBreakExtraOffset, out Value);

                case IndexBreakCount:
                    return Instance.WinHelper.TryReadUInt32(Attributes + WinSysHelper.DcAttrBreakCountOffset, out Value);

                case IndexSaveDepth:
                    Value = (uint)SaveDepth;
                    return true;

                // No font kerning pairs are stored.
                case IndexFontLanguageInfo:
                    Value = GcpError;
                    return true;

                case IndexMemoryDc:
                    Value = MemoryDc ? 1u : 0u;
                    return true;

                case IndexMapMode:
                    return Instance.WinHelper.TryReadUInt32(Attributes + WinSysHelper.DcAttrMapModeOffset, out Value);

                default:
                    Value = 0;
                    return false;
            }
        }
    }
}
