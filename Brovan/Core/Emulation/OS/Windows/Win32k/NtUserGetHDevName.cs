using System;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetHDevName : IWinSyscall
    {
        private const int CchDeviceName = 32;
        private const string DeviceName = @"\\.\DISPLAY1";

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Monitor = Instance.WinHelper.GetArg(0);
            ulong NamePtr = Instance.WinHelper.GetArg(1);

            uint NameBytes = CchDeviceName * sizeof(char);

            if (NamePtr == 0 || !Instance.IsRegionMapped(NamePtr, NameBytes) ||
                Monitor == 0 || Monitor != Instance.WinHelper.GetPrimaryMonitorHandle())
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(NameBytes);
            Buffer.Clear();
            Encoding.Unicode.GetBytes(DeviceName, Buffer);

            if (!Instance.WriteMemory(NamePtr, Buffer))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
