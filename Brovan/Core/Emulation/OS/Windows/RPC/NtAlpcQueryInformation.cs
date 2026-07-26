using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcQueryInformation : IWinSyscall
    {
        private const uint AlpcBasicInformation = 0;
        private const uint AlpcPortInformation = 1;
        private const uint AlpcAssociateCompletionPortInformation = 2;
        private const uint AlpcConnectedSIDInformation = 3;
        private const uint AlpcServerInformation = 4;
        private const uint AlpcMessageZoneInformation = 5;
        private const uint AlpcRegisterCompletionListInformation = 6;
        private const uint AlpcUnregisterCompletionListInformation = 7;
        private const uint AlpcServerSessionInformation = 12;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PortHandle = Instance.WinHelper.GetArg(0);
            uint InformationClass = (uint)Instance.WinHelper.GetArg(1);
            ulong InformationPtr = Instance.WinHelper.GetArg(2);
            uint Length = (uint)Instance.WinHelper.GetArg(3);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg(4);

            if (PortHandle != 0 && Instance.WinHelper.HandleManager.GetObjectByHandle<WinPort>(PortHandle) == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            uint RequiredLength = InformationClass switch
            {
                AlpcBasicInformation => (uint)(2 * sizeof(uint) + Instance.WinHelper.PointerSize),
                AlpcServerSessionInformation => 2 * sizeof(uint),
                AlpcAssociateCompletionPortInformation or AlpcRegisterCompletionListInformation or
                AlpcUnregisterCompletionListInformation or AlpcMessageZoneInformation => 0,
                _ => 0,
            };

            if (ReturnLengthPtr != 0)
            {
                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
            }

            if (RequiredLength == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (Length < RequiredLength)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (InformationPtr == 0 || !Instance.IsRegionMapped(InformationPtr, RequiredLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.WinHelper.WriteZeroMemory(InformationPtr, RequiredLength);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtAlpcQueryInformation: class {InformationClass}, length {Length}", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
