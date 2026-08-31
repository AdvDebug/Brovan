using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetTextMetricsW : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong BufferPtr = Instance.WinHelper.GetArg(1);
            uint BufferSize = (uint)Instance.WinHelper.GetArg(2);

            if (BufferPtr == 0 || BufferSize < Win32kHelper.TextMetricWSize)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.WinHelper.GetTextMetrics(Win32kHelper.ResolveDcFont(Instance, Hdc), out TextMetricsData Metrics))
                Metrics = Win32kHelper.DefaultTextMetrics;

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Win32kHelper.TextMetricWSize);
            Win32kHelper.WriteTextMetricsW(Buffer, Metrics);

            if (!Instance.WriteMemory(BufferPtr, Buffer.Slice(0, Win32kHelper.TextMetricWSize)))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
