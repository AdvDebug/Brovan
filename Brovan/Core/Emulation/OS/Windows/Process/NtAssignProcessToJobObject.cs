using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAssignProcessToJobObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong JobHandle = Instance.WinHelper.GetArg(0);
                ulong ProcessHandle = Instance.WinHelper.GetArg(1);
                return Instance.WinHelper.AssignProcessToJobHandle(JobHandle, ProcessHandle);
            }

            uint JobHandle32 = (uint)Instance.WinHelper.GetArg(0);
            uint ProcessHandle32 = (uint)Instance.WinHelper.GetArg(1);
            return Instance.WinHelper.AssignProcessToJobHandle(JobHandle32, ProcessHandle32);
        }
    }
}
