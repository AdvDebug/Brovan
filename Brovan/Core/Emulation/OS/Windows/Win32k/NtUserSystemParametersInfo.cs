using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSystemParametersInfo : IWinSyscall
    {
        private const uint SpiGetBeep = 0x0001;
        private const uint SpiGetMouse = 0x0003;
        private const uint SpiGetKeyboardSpeed = 0x000A;
        private const uint SpiGetScreenSaveActive = 0x0010;
        private const uint SpiSetScreenSaveActive = 0x0011;
        private const uint SpiGetKeyboardDelay = 0x0016;
        private const uint SpiGetWorkArea = 0x0030;
        private const uint SpiGetScreenReader = 0x0046;
        private const uint SpiGetWheelScrollLines = 0x0068;
        private const uint SpiGetWheelScrollChars = 0x006C;
        private const uint SpiGetMouseSpeed = 0x0070;

        private const uint DefaultKeyboardSpeed = 31;
        private const uint DefaultKeyboardDelay = 1;
        private const uint DefaultWheelScrollLines = 3;
        private const uint DefaultWheelScrollChars = 3;
        private const uint DefaultMouseSpeed = 10;
        private const uint DefaultMouseThreshold1 = 6;
        private const uint DefaultMouseThreshold2 = 10;
        private const uint DefaultMouseAcceleration = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Action = Instance.WinHelper.GetArg32(0);
            ulong ParameterPtr = Instance.WinHelper.GetArg(2);

            switch (Action)
            {
                case SpiGetWorkArea:
                {
                    if (!Instance.WinHelper.TryGetPrimaryMonitorRect(out int Left, out int Top, out int Right, out int Bottom))
                        break;

                    Span<uint> Rect = stackalloc uint[4] { (uint)Left, (uint)Top, (uint)Right, (uint)Bottom };
                    if (!TryWriteDwords(Instance, ParameterPtr, Rect))
                        break;

                    Instance.SetRawSyscallReturn(1);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SpiGetMouse:
                {
                    Span<uint> Mouse = stackalloc uint[3] { DefaultMouseThreshold1, DefaultMouseThreshold2, DefaultMouseAcceleration };
                    if (!TryWriteDwords(Instance, ParameterPtr, Mouse))
                        break;

                    Instance.SetRawSyscallReturn(1);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SpiGetBeep:
                case SpiGetScreenSaveActive:
                case SpiGetScreenReader:
                {
                    Span<uint> Disabled = stackalloc uint[1] { 0 };
                    if (!TryWriteDwords(Instance, ParameterPtr, Disabled))
                        break;

                    Instance.SetRawSyscallReturn(1);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SpiGetKeyboardSpeed:
                case SpiGetKeyboardDelay:
                case SpiGetWheelScrollLines:
                case SpiGetWheelScrollChars:
                case SpiGetMouseSpeed:
                {
                    uint Value = Action switch
                    {
                        SpiGetKeyboardSpeed => DefaultKeyboardSpeed,
                        SpiGetKeyboardDelay => DefaultKeyboardDelay,
                        SpiGetWheelScrollLines => DefaultWheelScrollLines,
                        SpiGetWheelScrollChars => DefaultWheelScrollChars,
                        _ => DefaultMouseSpeed,
                    };

                    Span<uint> Single = stackalloc uint[1] { Value };
                    if (!TryWriteDwords(Instance, ParameterPtr, Single))
                        break;

                    Instance.SetRawSyscallReturn(1);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                case SpiSetScreenSaveActive:
                {
                    Instance.SetRawSyscallReturn(1);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                default:
                    Instance.TriggerEventMessage($"[!] NtUserSystemParametersInfo: action 0x{Action:X} is not implemented.", LogFlags.Issues);
                    break;
            }

            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool TryWriteDwords(BinaryEmulator Instance, ulong Address, ReadOnlySpan<uint> Values)
        {
            if (Address == 0 || !Instance.IsRegionMapped(Address, (ulong)(Values.Length * sizeof(uint))))
                return false;

            for (int i = 0; i < Values.Length; i++)
                Instance._emulator.WriteMemory(Address + (ulong)(i * sizeof(uint)), Values[i], sizeof(uint));

            return true;
        }
    }
}
