using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryDirectoryFile : IWinSyscall
    {
        private const uint SL_RESTART_SCAN = 0x01;
        private const uint SL_RETURN_SINGLE_ENTRY = 0x02;

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
            bool ReturnSingleEntry = (uint)Instance.WinHelper.GetArg(8) != 0;
            ulong FileName = Instance.WinHelper.GetArg(9);
            bool RestartScan = (uint)Instance.WinHelper.GetArg(10) != 0;

            uint QueryFlags = 0;
            if (RestartScan)
                QueryFlags |= SL_RESTART_SCAN;
            if (ReturnSingleEntry)
                QueryFlags |= SL_RETURN_SINGLE_ENTRY;

            return NtQueryDirectoryFileCommon.Handle(Instance, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
        }
    }
}
