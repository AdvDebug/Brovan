using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWaitForMultipleObjects : IWinSyscall
    {
        private const uint MaximumWaitObjects = 64;
        private const uint WaitAny = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            uint Count = (uint)Instance.WinHelper.GetArg(0);
            ulong HandlesPtr = Instance.WinHelper.GetArg(1);
            uint WaitType = (uint)Instance.WinHelper.GetArg(2);
            bool Alertable = (byte)Instance.WinHelper.GetArg(3) != 0;
            ulong TimeoutPtr = Instance.WinHelper.GetArg(4);

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.WaitCompleted)
            {
                NTSTATUS Status = State.WaitStatus;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
                return Status;
            }

            if (Thread.WaitActive)
                return Instance.ContinueObjectWait(Thread, State);

            if (Count == 0 || Count > MaximumWaitObjects)
                return NTSTATUS.STATUS_INVALID_PARAMETER_1;

            if (WaitType > WaitAny)
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            if (!Instance.WinHelper.TryReadTimeout(TimeoutPtr, out long? Timeout))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint HandleSize = (uint)Instance.WinHelper.PointerSize;
            Span<byte> Handles = stackalloc byte[(int)(MaximumWaitObjects * 8)];
            Handles = Handles.Slice(0, (int)(Count * HandleSize));
            if (!Instance.ReadMemory(HandlesPtr, Handles))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            bool WaitAll = WaitType != WaitAny;
            NTSTATUS Resolved = Instance.ResolveWaitHandles(State, Handles, HandleSize, WaitAll);
            if (Resolved != NTSTATUS.STATUS_SUCCESS)
                return Resolved;

            return Instance.WaitForObjects(Thread, State, WaitAll, Alertable, Timeout);
        }
    }
}
