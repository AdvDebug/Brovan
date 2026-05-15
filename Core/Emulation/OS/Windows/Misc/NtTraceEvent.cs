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
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong TraceHandle = Instance.WinHelper.GetArg64(0);
                uint Flags = (uint)Instance.WinHelper.GetArg64(1);
                uint FieldSize = (uint)Instance.WinHelper.GetArg64(2);
                ulong Fields = Instance.WinHelper.GetArg64(3);

                if (FieldSize != 0)
                {
                    if (Fields == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(Fields, FieldSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                Instance.TriggerEventMessage($"[+] NtTraceEvent: TraceHandle=0x{TraceHandle:X}, Flags=0x{Flags:X}, FieldSize=0x{FieldSize:X}.", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }
            else
            {
                uint ESP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
                uint TraceHandle = Instance.ReadMemoryUInt(ESP + 4);
                uint Flags = Instance.ReadMemoryUInt(ESP + 8);
                uint FieldSize = Instance.ReadMemoryUInt(ESP + 12);
                uint Fields = Instance.ReadMemoryUInt(ESP + 16);

                if (FieldSize != 0)
                {
                    if (Fields == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(Fields, FieldSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                Instance.TriggerEventMessage($"[+] NtTraceEvent (x86): TraceHandle=0x{TraceHandle:X}, Flags=0x{Flags:X}, FieldSize=0x{FieldSize:X}.", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }
        }
    }
}
