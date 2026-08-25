using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetRawInputDeviceInfo : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DeviceHandle = Instance.WinHelper.GetArg(0);
            uint Command = (uint)Instance.WinHelper.GetArg(1);
            ulong DataPtr = Instance.WinHelper.GetArg(2);
            ulong SizePtr = Instance.WinHelper.GetArg(3);

            if (SizePtr == 0 || !Instance.IsRegionMapped(SizePtr, 4))
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            if (!Win32kRawInput.TryGetDevice(DeviceHandle, out Win32kRawDevice Device))
                return Fail(Instance, Win32kHelper.ERROR_INVALID_HANDLE);

            switch (Command)
            {
                case Win32kRawInput.RIDI_DEVICENAME:
                    return WriteDeviceName(Instance, Device, DataPtr, SizePtr);

                case Win32kRawInput.RIDI_DEVICEINFO:
                    return WriteDeviceInfo(Instance, Device, DataPtr, SizePtr);

                // A mouse or a keyboard is not reported through a HID collection, so there is nothing to parse.
                case Win32kRawInput.RIDI_PREPARSEDDATA:
                    Instance._emulator.WriteMemory(SizePtr, 0u, 4);
                    Instance.SetLastWinError(0);
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;

                default:
                    return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);
            }
        }

        private static NTSTATUS WriteDeviceName(BinaryEmulator Instance, in Win32kRawDevice Device, ulong DataPtr, ulong SizePtr)
        {
            uint Characters = (uint)Device.Name.Length + 1;

            if (DataPtr == 0)
            {
                Instance._emulator.WriteMemory(SizePtr, Characters, 4);
                Instance.SetLastWinError(0);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint Capacity = Instance.ReadMemoryUInt(SizePtr);
            if (Capacity < Characters)
            {
                Instance._emulator.WriteMemory(SizePtr, Characters, 4);
                return Fail(Instance, Win32kHelper.ERROR_INSUFFICIENT_BUFFER);
            }

            uint Bytes = Characters * 2;
            if (!Instance.IsRegionMapped(DataPtr, Bytes))
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Bytes);
            Buffer.Clear();
            Encoding.Unicode.GetBytes(Device.Name, Buffer);

            if (!Instance.WriteMemory(DataPtr, Buffer))
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Characters);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS WriteDeviceInfo(BinaryEmulator Instance, in Win32kRawDevice Device, ulong DataPtr, ulong SizePtr)
        {
            if (DataPtr == 0)
            {
                Instance._emulator.WriteMemory(SizePtr, Win32kRawInput.DeviceInfoSize, 4);
                Instance.SetLastWinError(0);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint Capacity = Instance.ReadMemoryUInt(SizePtr);
            if (Capacity < Win32kRawInput.DeviceInfoSize)
            {
                Instance._emulator.WriteMemory(SizePtr, Win32kRawInput.DeviceInfoSize, 4);
                return Fail(Instance, Win32kHelper.ERROR_INSUFFICIENT_BUFFER);
            }

            if (!Instance.IsRegionMapped(DataPtr, Win32kRawInput.DeviceInfoSize))
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Win32kRawInput.DeviceInfoSize);
            Win32kRawInput.WriteDeviceInfo(Buffer, Device);

            if (!Instance.WriteMemory(DataPtr, Buffer))
                return Fail(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Win32kRawInput.DeviceInfoSize);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS Fail(BinaryEmulator Instance, uint Error)
        {
            Instance.SetLastWinError(Error);
            Instance.SetRawSyscallReturn(uint.MaxValue);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
