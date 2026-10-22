using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIGetCachedHybridQueryValue : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);

            Span<byte> Arguments = stackalloc byte[Win32kDxgk.HybridQuerySize];
            if (!Instance.ReadMemory(ArgumentsPtr, Arguments))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint QueryType = BinaryPrimitives.ReadUInt32LittleEndian(Arguments.Slice(Win32kDxgk.OffsetHybridQueryType));
            if (QueryType == Win32kDxgk.HybridQueryAdapter)
                return Instance.WinUnimplemented;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            uint State = QueryType == Win32kDxgk.HybridQueryProcess1 ? Process.HybridQueryState1
                : QueryType == Win32kDxgk.HybridQueryProcess2 ? Process.HybridQueryState2
                : 0;

            return Instance.WinHelper.WriteUInt32(ArgumentsPtr, State) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
