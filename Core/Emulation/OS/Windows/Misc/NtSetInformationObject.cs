using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetInformationObject : IWinSyscall
    {
        private const uint ObjectHandleFlagInformation = 4;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong Handle = Instance.WinHelper.GetArg64(0);
                uint ObjectInformationClass = (uint)Instance.WinHelper.GetArg64(1, true);
                ulong ObjectInformationPtr = Instance.WinHelper.GetArg64(2);
                uint Length = (uint)Instance.WinHelper.GetArg64(3, true);

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

                bool Inherit = Data[0] != 0;
                bool ProtectFromClose = Data[1] != 0;

                ObjectHandleFlags Flags = ObjectHandleFlags.None;
                if (Inherit)
                    Flags |= ObjectHandleFlags.Inherit;
                if (ProtectFromClose)
                    Flags |= ObjectHandleFlags.ProtectFromClose;

                if (!Instance.WinHelper.HandleManager.SetHandleFlags(Handle, Flags))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                return NTSTATUS.STATUS_SUCCESS;
            }
            else
            {
                uint Handle32 = Instance.WinHelper.GetArg32(0);
                uint ObjectInformationClass = Instance.WinHelper.GetArg32(1);
                uint ObjectInformationPtr32 = Instance.WinHelper.GetArg32(2);
                uint Length = Instance.WinHelper.GetArg32(3);

                ulong Handle = Handle32;
                ulong ObjectInformationPtr = ObjectInformationPtr32;

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

                bool Inherit = Data[0] != 0;
                bool ProtectFromClose = Data[1] != 0;

                ObjectHandleFlags Flags = ObjectHandleFlags.None;
                if (Inherit)
                    Flags |= ObjectHandleFlags.Inherit;
                if (ProtectFromClose)
                    Flags |= ObjectHandleFlags.ProtectFromClose;

                if (!Instance.WinHelper.HandleManager.SetHandleFlags(Handle, Flags))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                return NTSTATUS.STATUS_SUCCESS;
            }
        }
    }
}