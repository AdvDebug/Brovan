using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetInformationObject : IWinSyscall
    {
        private const uint ObjectHandleFlagInformation = 4;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Handle = Instance.WinHelper.GetArg(0);
            uint ObjectInformationClass = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectInformationPtr = Instance.WinHelper.GetArg(2);
            uint Length = (uint)Instance.WinHelper.GetArg(3);

            if (!Instance.WinHelper.HandleExists(Handle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (ObjectInformationClass != ObjectHandleFlagInformation)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            if (ObjectInformationPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Length < 2)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(ObjectInformationPtr, 2))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            byte[] Data = Instance.ReadMemory(ObjectInformationPtr, 2);
            if (Data == null || Data.Length < 2)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ObjectHandleFlags Flags = ObjectHandleFlags.None;
            if (Data[0] != 0)
                Flags |= ObjectHandleFlags.Inherit;
            if (Data[1] != 0)
                Flags |= ObjectHandleFlags.ProtectFromClose;

            if (!Instance.WinHelper.HandleManager.SetHandleFlags(Handle, Flags))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}