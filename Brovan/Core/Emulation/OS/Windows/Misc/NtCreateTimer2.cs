using System;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateTimer2 : IWinSyscall
    {
        // NT accepts bit 31 and only these combinations of bits 1 to 3 (ExpExTimerAttributesAreValid).
        private const uint AttributeMask = 0x8000000E;
        private const uint KindMask = 0xE;
        private static readonly uint[] ValidKinds = { 0, 2, 4, 8, 6, 0xC };

        private const uint MaxIRTimerId = 19;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            ulong TimerHandlePtr = Helper.GetArg(0);
            ulong IRTimerIdPtr = Helper.GetArg(1);
            ulong ObjectAttributesPtr = Helper.GetArg(2);
            uint Attributes = (uint)Helper.GetArg(3);
            AccessMask DesiredAccess = (AccessMask)(uint)Helper.GetArg(4);

            if ((Attributes & AttributeMask) != Attributes || Array.IndexOf(ValidKinds, Attributes & KindMask) < 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_4;

            if (ObjectAttributesPtr != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            bool IRTimer = (Attributes & WinIRTimer.IRTimerAttribute) != 0;
            if (IRTimerIdPtr != 0 && !IRTimer)
                return NTSTATUS.STATUS_INVALID_PARAMETER_2;

            if (Helper.ProbeForWrite(TimerHandlePtr, (uint)Helper.PointerSize) != NTSTATUS.STATUS_SUCCESS)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (IRTimer)
            {
                uint Id = 0;
                if (IRTimerIdPtr != 0 && !Helper.TryReadUInt32(IRTimerIdPtr, out Id))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if ((ushort)Id - 1u >= MaxIRTimerId)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                Utils.LogError($"[-] NtCreateTimer2: IR timer id 0x{Id:X8} is not served.");
                return Instance.WinUnimplemented;
            }

            WinHandle Handle = Helper.CreateIRTimerHandle(Attributes, DesiredAccess);
            if (!Helper.WritePointer(TimerHandlePtr, Handle.Handle))
            {
                Helper.CloseHandle(Handle.Handle);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
