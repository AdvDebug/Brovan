using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDICacheHybridQueryValue : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            Span<byte> Arguments = stackalloc byte[Win32kDxgk.HybridQuerySize];
            if (!Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            uint State = BinaryPrimitives.ReadUInt32LittleEndian(Arguments);
            switch (BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(Win32kDxgk.OffsetHybridQueryType)))
            {
                case Win32kDxgk.HybridQueryAdapter:
                    return Instance.WinUnimplemented;
                case Win32kDxgk.HybridQueryProcess1:
                    State = CacheOnce(ref Process.HybridQueryState1, State);
                    break;
                case Win32kDxgk.HybridQueryProcess2:
                    State = CacheOnce(ref Process.HybridQueryState2, State);
                    break;
            }

            return Instance.WinHelper.WriteUInt32(ArgumentsPtr, State) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        private static uint CacheOnce(ref uint Cached, uint State)
        {
            if (Cached == 0)
                Cached = State;

            return Cached;
        }
    }
}
