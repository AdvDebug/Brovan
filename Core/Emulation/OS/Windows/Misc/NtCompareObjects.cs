namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCompareObjects : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong FirstHandle = Instance.WinHelper.GetArg64(0);
            ulong SecondHandle = Instance.WinHelper.GetArg64(1);

            NTSTATUS Status = ResolveObject(Instance, FirstHandle, out IHandleObject FirstObject);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = ResolveObject(Instance, SecondHandle, out IHandleObject SecondObject);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return ReferenceEquals(FirstObject, SecondObject) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_NOT_SAME_OBJECT;
        }

        private static NTSTATUS ResolveObject(BinaryEmulator Instance, ulong Handle, out IHandleObject Object)
        {
            Object = null;

            // check if it is the current process
            if (Handle == HandleManager.CurrentProcess || Handle == uint.MaxValue)
            {
                Object = Instance.WinHelper.WinProcesses.FirstOrDefault(Process => Process.PID == Instance.WinHelper.PID);
                return Object != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_HANDLE;
            }

            // check if it is the current thread
            if (Handle == HandleManager.CurrentThread || Handle == 0xFFFFFFFEu)
            {
                Object = Instance.CurrentThread;
                return Object != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_HANDLE;
            }

            Object = Instance.WinHelper.HandleManager.GetObjectByHandle(Handle);
            return Object != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_HANDLE;
        }
    }
}