using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class ConsoleServer : IWinDevice
    {
        public string DeviceName => "\\Device\\ConDrv";

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DevicePath;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        public static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Data.OutputBuffer != null && Data.OutputBuffer.Length > 0)
            {
                Array.Clear(Data.OutputBuffer, 0, Data.OutputBuffer.Length);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}