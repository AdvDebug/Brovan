using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtApphelpCacheControl : IWinSyscall
    {
        private enum AhcServiceClass : uint
        {
            ApphelpCacheServiceLookup = 0,
            ApphelpCacheServiceRemove = 1,
            ApphelpCacheServiceUpdate = 2,
            ApphelpCacheServiceClear = 3,
            ApphelpCacheServiceSnapStatistics = 4,
            ApphelpCacheServiceSnapCache = 5,
            ApphelpCacheServiceLookupCdb = 6,
            ApphelpCacheServiceRefreshCdb = 7,
            ApphelpCacheServiceMapQuirks = 8,
            ApphelpCacheServiceHwIdQuery = 9,
            ApphelpCacheServiceInitProcessData = 10,
            ApphelpCacheServiceLookupAndWriteToProcess = 11,
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                AhcServiceClass Service = (AhcServiceClass)(uint)Instance.WinHelper.GetArg(0);
                ulong ServiceData = Instance.WinHelper.GetArg(1);
                return HandleApphelpCacheControl(Instance, Service, ServiceData);
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                AhcServiceClass Service = (AhcServiceClass)Instance.WinHelper.GetArg32(0);
                uint ServiceData = Instance.WinHelper.GetArg32(1);
                return HandleApphelpCacheControl(Instance, Service, ServiceData);
            }

            return Instance.WinUnimplemented;
        }

        private static NTSTATUS HandleApphelpCacheControl(BinaryEmulator Instance, AhcServiceClass Service, ulong ServiceData)
        {
            if (ServiceData != 0 && !Instance.IsRegionMapped(ServiceData, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            switch (Service)
            {
                case AhcServiceClass.ApphelpCacheServiceLookup:
                case AhcServiceClass.ApphelpCacheServiceLookupCdb:
                case AhcServiceClass.ApphelpCacheServiceHwIdQuery:
                case AhcServiceClass.ApphelpCacheServiceLookupAndWriteToProcess:
                    if (ServiceData == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    return NTSTATUS.STATUS_NOT_FOUND;

                case AhcServiceClass.ApphelpCacheServiceRemove:
                case AhcServiceClass.ApphelpCacheServiceUpdate:
                case AhcServiceClass.ApphelpCacheServiceMapQuirks:
                case AhcServiceClass.ApphelpCacheServiceInitProcessData:
                    if (ServiceData == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    return NTSTATUS.STATUS_SUCCESS;

                case AhcServiceClass.ApphelpCacheServiceClear:
                case AhcServiceClass.ApphelpCacheServiceSnapStatistics:
                case AhcServiceClass.ApphelpCacheServiceSnapCache:
                case AhcServiceClass.ApphelpCacheServiceRefreshCdb:
                    return NTSTATUS.STATUS_SUCCESS;

                default:
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
            }
        }
    }
}
