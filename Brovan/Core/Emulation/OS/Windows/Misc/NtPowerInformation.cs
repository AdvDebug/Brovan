namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtPowerInformation : IWinSyscall
    {
        // Power information classes currently modeled by this syscall handler.
        public enum POWER_INFORMATION_LEVEL
        {
            SystemPowerCapabilities = 4,
            SystemBatteryState = 5,
        }

        public bool NeedInputBuffer(POWER_INFORMATION_LEVEL Level)
        {
            switch(Level)
            {
                default:
                    return false;
            }
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            POWER_INFORMATION_LEVEL InformationLevel = (POWER_INFORMATION_LEVEL)Instance.WinHelper.GetArg(0);
            ulong InputBuffer = Instance.WinHelper.GetArg(1);
            uint InputBufferLength = (uint)Instance.WinHelper.GetArg(2);
            ulong OutputBuffer = Instance.WinHelper.GetArg(3);
            uint OutputBufferLength = (uint)Instance.WinHelper.GetArg(4);

            if (!NeedInputBuffer(InformationLevel) && InputBuffer != 0)
            {
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            switch(InformationLevel)
            {
                case POWER_INFORMATION_LEVEL.SystemBatteryState:
                    {
                        uint RequiredSize = (uint)StructSerializer.GetStructSize<SYSTEM_BATTERY_STATE>(Instance);
                        if (OutputBufferLength < RequiredSize)
                        {
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
                        }

                        if (!Instance.IsRegionMapped(OutputBuffer, OutputBufferLength))
                        {
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        }

                        SYSTEM_BATTERY_STATE BatteryState = new SYSTEM_BATTERY_STATE();
                        BatteryState.AcOnLine = true;
                        BatteryState.BatteryPresent = false;
                        BatteryState.Charging = false;
                        BatteryState.Discharging = false;
                        BatteryState.Spare1 = new byte[3];
                        BatteryState.Tag = 0;
                        BatteryState.MaxCapacity = 0;
                        BatteryState.RemainingCapacity = 0;
                        BatteryState.Rate = 0;
                        BatteryState.EstimatedTime = 0;
                        BatteryState.DefaultAlert1 = 0;
                        BatteryState.DefaultAlert2 = 0;
                        if (!StructSerializer.WriteStruct(Instance, OutputBuffer, BatteryState).Success)
                        {
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        }
                        return NTSTATUS.STATUS_SUCCESS;
                    }
                case POWER_INFORMATION_LEVEL.SystemPowerCapabilities:
                    {
                        if (InputBuffer != 0 || InputBufferLength != 0)
                        {
                            return NTSTATUS.STATUS_INVALID_PARAMETER;
                        }

                        uint RequiredSize = (uint)StructSerializer.GetStructSize<SYSTEM_POWER_CAPABILITIES>(Instance);
                        if (OutputBufferLength < RequiredSize)
                        {
                            return NTSTATUS.STATUS_BUFFER_TOO_SMALL;
                        }

                        if (!Instance.IsRegionMapped(OutputBuffer, RequiredSize))
                        {
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        }

                        SYSTEM_POWER_CAPABILITIES Capabilities = new SYSTEM_POWER_CAPABILITIES();
                        Capabilities.PowerButtonPresent = true;
                        Capabilities.SleepButtonPresent = false;
                        Capabilities.LidPresent = false;
                        Capabilities.SystemS1 = false;
                        Capabilities.SystemS2 = false;
                        Capabilities.SystemS3 = false;
                        Capabilities.SystemS4 = false;
                        Capabilities.SystemS5 = true;
                        Capabilities.HiberFilePresent = false;
                        Capabilities.FullWake = false;
                        Capabilities.VideoDimPresent = false;
                        Capabilities.ApmPresent = false;
                        Capabilities.UpsPresent = false;
                        Capabilities.ThermalControl = false;
                        Capabilities.ProcessorThrottle = false;
                        Capabilities.ProcessorMinThrottle = 0;
                        Capabilities.ProcessorThrottleScale = 0;
                        Capabilities.Spare2 = new byte[4];
                        Capabilities.ProcessorMaxThrottle = 0;
                        Capabilities.FastSystemS4 = false;
                        Capabilities.Hiberboot = false;
                        Capabilities.WakeAlarmPresent = false;
                        Capabilities.AoAc = false;
                        Capabilities.DiskSpinDown = false;
                        Capabilities.Spare3 = new byte[6];
                        Capabilities.SystemBatteriesPresent = false;
                        Capabilities.BatteriesAreShortTerm = false;
                        Capabilities.BatteryScale = new BATTERY_REPORTING_SCALE[3];
                        Capabilities.BatteryScale[0] = new BATTERY_REPORTING_SCALE();
                        Capabilities.BatteryScale[1] = new BATTERY_REPORTING_SCALE();
                        Capabilities.BatteryScale[2] = new BATTERY_REPORTING_SCALE();
                        Capabilities.AcOnLineWake = 0;
                        Capabilities.SoftLidWake = 0;
                        Capabilities.RtcWake = 0;
                        Capabilities.MinDeviceWakeState = 0;
                        Capabilities.DefaultLowLatencyWake = 0;

                        if (!StructSerializer.WriteStruct(Instance, OutputBuffer, Capabilities).Success)
                        {
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        }

                        return NTSTATUS.STATUS_SUCCESS;
                    }
                default:
                    return Instance.WinUnimplemented;
            }
        }
    }
}
