using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ThreadHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ClientIdPtr = Instance.WinHelper.GetArg(3);

            if (ThreadHandlePtr == 0 || ClientIdPtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong Pid = Instance.WinHelper.ReadPointer(ClientIdPtr);
            ulong Tid = Instance.WinHelper.ReadPointer(ClientIdPtr + (ulong)Instance.WinHelper.PointerSize);

            if (Pid != 0 && Pid != Instance.WinHelper.PID)
                return NTSTATUS.STATUS_INVALID_CID;

            if (Tid > uint.MaxValue || !Instance.Threads.TryGetValue((uint)Tid, out EmulatedThread Thread) || Thread == null ||
                Thread.State == EmulatedThreadState.Terminated)
                return NTSTATUS.STATUS_INVALID_CID;

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Thread, (AccessMask)DesiredAccess);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance.WinHelper.WritePointer(ThreadHandlePtr, Handle.Handle))
            {
                Instance.WinHelper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
