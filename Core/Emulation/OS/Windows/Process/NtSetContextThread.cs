using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetContextThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ThreadHandle = Instance.WinHelper.GetArg64(0);
            ulong ContextPtr = Instance.WinHelper.GetArg64(1);

            EmulatedThread Thread = WindowsThreadContext64.ResolveThread(Instance, ThreadHandle);
            if (Thread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!WindowsThreadContext64.HasThreadAccess(Instance, ThreadHandle, AccessMask.ThreadSetContext))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            NTSTATUS Status = WindowsThreadContext64.TryReadContextFlags(Instance, ContextPtr, out uint Flags);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            WindowsThreadContext64.ApplyContext(Instance, Thread, ContextPtr, Flags);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
