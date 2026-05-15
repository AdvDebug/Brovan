using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryDirectoryFileEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong FileHandle = Instance.WinHelper.GetArg64(0);
            ulong EventHandle = Instance.WinHelper.GetArg64(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg64(2);
            ulong ApcContext = Instance.WinHelper.GetArg64(3);
            ulong IoStatusBlock = Instance.WinHelper.GetArg64(4);
            ulong FileInformation = Instance.WinHelper.GetArg64(5);
            uint Length = (uint)Instance.WinHelper.GetArg64(6);
            uint FileInformationClass = (uint)Instance.WinHelper.GetArg64(7);
            uint QueryFlags = (uint)Instance.WinHelper.GetArg64(8);
            ulong FileName = Instance.WinHelper.GetArg64(9);

            return NtQueryDirectoryFileCommon.Handle(Instance, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
        }
    }
}
