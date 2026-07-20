using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTraceEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            {
                ulong TraceHandle = Instance.WinHelper.GetArg(0);
                uint Flags = (uint)Instance.WinHelper.GetArg(1);
                uint FieldSize = (uint)Instance.WinHelper.GetArg(2);
                ulong Fields = Instance.WinHelper.GetArg(3);

                if (FieldSize != 0)
                {
                    if (Fields == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(Fields, FieldSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtTraceEvent: TraceHandle=0x{TraceHandle:X}, Flags=0x{Flags:X}, FieldSize=0x{FieldSize:X}.", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }
        }
    }
}
