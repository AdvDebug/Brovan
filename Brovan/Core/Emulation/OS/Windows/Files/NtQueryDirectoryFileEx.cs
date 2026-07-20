using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryDirectoryFileEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong EventHandle = Instance.WinHelper.GetArg(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg(2);
            ulong ApcContext = Instance.WinHelper.GetArg(3);
            ulong IoStatusBlock = Instance.WinHelper.GetArg(4);
            ulong FileInformation = Instance.WinHelper.GetArg(5);
            uint Length = (uint)Instance.WinHelper.GetArg(6);
            uint FileInformationClass = (uint)Instance.WinHelper.GetArg(7);
            uint QueryFlags = (uint)Instance.WinHelper.GetArg(8);
            ulong FileName = Instance.WinHelper.GetArg(9);

            return NtQueryDirectoryFileCommon.Handle(Instance, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
        }
    }
}
