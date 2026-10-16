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
            bool ReturnSingleEntry = (byte)Instance.WinHelper.GetArg(8) != 0;
            ulong FileName = Instance.WinHelper.GetArg(9);
            bool RestartScan = (byte)Instance.WinHelper.GetArg(10) != 0;

            if (Instance.IsX86Guest && !Wow64ForwardsClass(FileInformationClass))
                return NTSTATUS.STATUS_NOT_IMPLEMENTED;

            uint QueryFlags = 0;
            if (RestartScan)
                QueryFlags |= SL_RESTART_SCAN;
            if (ReturnSingleEntry)
                QueryFlags |= SL_RETURN_SINGLE_ENTRY;

            return NtQueryDirectoryFileCommon.Handle(Instance, FileHandle, EventHandle, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
        }

        // whNtQueryDirectoryFile in wow64.dll forwards only these classes. The Ex thunk forwards every class.
        private static bool Wow64ForwardsClass(uint FileInformationClass) => FileInformationClass switch
        {
            1 or 2 or 3 or 12 or 29 or 32 or 33 or 37 or 38 or 39 or 50 or 60 or 63 or 78 or 79 or 80 or 81 => true,
            _ => false,
        };
    }
}
