namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetCurrentDpiInfo : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Monitor = Instance.WinHelper.GetArg(0);
            ulong InfoPtr = Instance.WinHelper.GetArg(1);

            if (Monitor == 0 || Monitor != Instance.WinHelper.GetPrimaryMonitorHandle())
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Info = stackalloc byte[Win32kDpi.DpiInformationSize];
            Win32kDpi.FillDpiInformation(Info);

            if (Instance.WinHelper.ProbeForWrite(InfoPtr, (uint)Info.Length) != NTSTATUS.STATUS_SUCCESS)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Instance.WriteMemory(InfoPtr, Info) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }
}
