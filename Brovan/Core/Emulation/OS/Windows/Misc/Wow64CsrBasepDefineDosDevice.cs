using Brovan.Core.Emulation.OS.Windows.RPC.Ports;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class Wow64CsrBasepDefineDosDevice : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Flags = (uint)Instance.WinHelper.GetArg(0);
            uint DeviceNamePtr = (uint)Instance.WinHelper.GetArg(1);
            uint TargetPathPtr = (uint)Instance.WinHelper.GetArg(2);

            if (!Instance.WinHelper.TryReadUnicodeString32(DeviceNamePtr, out string DeviceName, out NTSTATUS Status))
                return Status;

            if (!Instance.WinHelper.TryReadUnicodeString32(TargetPathPtr, out string TargetPath, out Status))
                return Status;

            return CsrssPortHandler.DefineDosDevice(Instance, Flags, DeviceName.ToUpperInvariant(), TargetPath);
        }
    }
}
