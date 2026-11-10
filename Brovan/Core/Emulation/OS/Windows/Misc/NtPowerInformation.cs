using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtPowerInformation : IWinSyscall
    {
        // Power information classes currently modeled by this syscall handler.
        public enum POWER_INFORMATION_LEVEL
        {
            SystemPowerCapabilities = 4,
            SystemBatteryState = 5,
            PowerSettingNotificationName = 58,
            PowerSettingValue = 59,
        }

        // NT: a GUID and a session id.
        private const uint SettingKeySize = 0x14;
        private const int GuidSize = 16;

        // NT writes three record sizes, then each record as change stamp, length and data (PopMarshalSettingValues).
        private const int SettingRecordCount = 3;
        private const int SettingRecordHeaderSize = 8;

        // NT publishes the AC/DC power source first, so its change stamp is 1 (PopInitilizeAcDcSettings). Every record
        // carries the current source, which is AC to match SystemBatteryState.
        private static readonly Guid AcDcPowerSource = new Guid("5d3e9a59-e9d5-4b00-a6bd-ff34ff516548");
        private const uint AcDcPowerSourceStamp = 1;
        private const uint PoAc = 0;

        public bool NeedInputBuffer(POWER_INFORMATION_LEVEL Level)
        {
            switch(Level)
            {
                case POWER_INFORMATION_LEVEL.PowerSettingNotificationName:
                case POWER_INFORMATION_LEVEL.PowerSettingValue:
                    return true;
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
                case POWER_INFORMATION_LEVEL.PowerSettingNotificationName:
                    return QuerySettingNotificationName(Instance, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
                case POWER_INFORMATION_LEVEL.PowerSettingValue:
                    return QuerySettingValue(Instance, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
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

        // NT: no input names the setting set, and a setting that was never published is not found
        // (PopGetSettingNotificationName). Brovan publishes only the AC/DC power source.
        private static NTSTATUS QuerySettingNotificationName(BinaryEmulator Instance, ulong InputBuffer, uint InputBufferLength, ulong OutputBuffer, uint OutputBufferLength)
        {
            if (OutputBuffer == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((InputBuffer != 0 && InputBufferLength != SettingKeySize) || OutputBufferLength != sizeof(ulong))
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            ulong Name = WnfStateNames.PowerSettingSetName;
            if (InputBuffer != 0)
            {
                Span<byte> Key = stackalloc byte[(int)SettingKeySize];
                if (!Instance.ReadMemory(InputBuffer, Key))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (new Guid(Key.Slice(0, GuidSize)) != AcDcPowerSource)
                    return NTSTATUS.STATUS_NOT_FOUND;

                Name = WnfStateNames.AcDcPowerSourceName;
            }

            return Instance.WinHelper.WriteUInt64(OutputBuffer, Name) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        // NT returns STATUS_INVALID_PARAMETER for a setting that was never published (PopGetSettingValue).
        private static NTSTATUS QuerySettingValue(BinaryEmulator Instance, ulong InputBuffer, uint InputBufferLength, ulong OutputBuffer, uint OutputBufferLength)
        {
            if (InputBuffer == 0 || OutputBuffer == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (InputBufferLength != GuidSize || OutputBufferLength < sizeof(uint))
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            Span<byte> Setting = stackalloc byte[GuidSize];
            if (!Instance.ReadMemory(InputBuffer, Setting))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (new Guid(Setting) != AcDcPowerSource)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            const int RecordsSize = SettingRecordCount * (SettingRecordHeaderSize + sizeof(uint));
            if (OutputBufferLength - sizeof(uint) < RecordsSize)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            Span<byte> Values = stackalloc byte[sizeof(uint) + RecordsSize];
            BinaryPrimitives.WriteUInt32LittleEndian(Values, RecordsSize);
            for (int Index = 0; Index < SettingRecordCount; Index++)
            {
                Span<byte> Record = Values.Slice(sizeof(uint) + Index * (SettingRecordHeaderSize + sizeof(uint)));
                BinaryPrimitives.WriteUInt32LittleEndian(Record, AcDcPowerSourceStamp);
                BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(4), sizeof(uint));
                BinaryPrimitives.WriteUInt32LittleEndian(Record.Slice(8), PoAc);
            }

            return Instance.WriteMemory(OutputBuffer, Values) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }
}
