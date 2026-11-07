using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetKerningPairs : IWinSyscall
    {
        private static readonly int PairBytes = Unsafe.SizeOf<KerningPairData>();
        private static readonly uint MaxPairs = Win32kHelper.MaxGdiBufferBytes / (uint)PairBytes;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            uint Count = (uint)Instance.WinHelper.GetArg(1);
            ulong PairsPtr = Instance.WinHelper.GetArg(2);

            Instance.SetRawSyscallReturn(Read(Instance, Hdc, Count, PairsPtr));
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static uint Read(BinaryEmulator Instance, ulong Hdc, uint Count, ulong PairsPtr)
        {
            if (PairsPtr != 0 && (Count == 0 || Count > MaxPairs))
                return 0;

            if (!Win32kHelper.IsKnownDc(Instance, Hdc) || !Win32kHelper.TryGetRealizedFont(Instance, Hdc, out ITextMetricsSupport Text, out IntPtr Font))
                return 0;

            uint Total = Text.GetKerningPairs(Font, Span<KerningPairData>.Empty);
            if (PairsPtr == 0)
                return Total;

            uint Copied = Math.Min(Total, Count);
            if (Copied == 0)
                return 0;

            using CallBuffer Buffer = new CallBuffer((int)Copied * PairBytes);
            uint Got = Text.GetKerningPairs(Font, MemoryMarshal.Cast<byte, KerningPairData>(Buffer.Span));
            return Got == Copied && Instance.WriteMemory(PairsPtr, Buffer.Span) ? Got : 0;
        }
    }
}
