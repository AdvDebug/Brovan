using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIGetContextInProcessSchedulingPriority : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (!Win32kDxgk.TryReadHandleArgument(Instance, out uint Handle) || !Instance.WinHelper.DxgkProcess.TryGet(Handle, out DxgkContext Context))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong ArgumentsPtr = Instance.WinHelper.GetArg(0);
            Span<byte> Arguments = stackalloc byte[NtGdiDdDDISetContextInProcessSchedulingPriority.ArgumentsSize];
            if (Instance.WinHelper.ProbeForWrite(ArgumentsPtr, (uint)Arguments.Length) != NTSTATUS.STATUS_SUCCESS)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            BinaryPrimitives.WriteUInt32LittleEndian(Arguments, Handle);
            BinaryPrimitives.WriteUInt32LittleEndian(Arguments.Slice(NtGdiDdDDISetContextInProcessSchedulingPriority.OffsetPriority), Context.InProcessPriority);
            return Instance.WriteMemory(ArgumentsPtr, Arguments) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
