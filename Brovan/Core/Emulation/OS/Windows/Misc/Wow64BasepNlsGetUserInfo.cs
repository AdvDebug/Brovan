namespace Brovan.Core.Emulation.OS.Windows
{
    internal class Wow64BasepNlsGetUserInfo : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong CachePtr = Instance.WinHelper.GetArg(0);
            uint CacheSize = (uint)Instance.WinHelper.GetArg(1);

            if (CachePtr == 0 || CacheSize == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(CachePtr, CacheSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // No per-user locale overrides, so the cache stays empty and the guest falls back to the registry.
            if (!Instance.WinHelper.WriteZeroMemory(CachePtr, CacheSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
