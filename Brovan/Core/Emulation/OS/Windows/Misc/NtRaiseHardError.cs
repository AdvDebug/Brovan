using System;
using System.Buffers.Binary;
using System.Threading.Tasks;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtRaiseHardError : IWinSyscall
    {
        private const uint MaxOption = 8;
        private const uint OptionShutdownSystem = 6;
        private const uint OverrideErrorMode = 0x10000000;
        private const uint ProcessShowsHardErrors = 1;
        private const ulong TebHardErrorMode = 0x16B0;
        private const uint ThreadFailCriticalErrors = 0x10;
        private const uint MaxResponse = 10;
        private const int UnicodeString64Size = 16;
        private const int UnicodeString32Size = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            ulong ResponsePtr = Helper.GetArg(5);

            Task<uint> Answered = Helper.TakeRetriedHostWork<Task<uint>>();
            if (Answered != null)
                return Reply(Instance, ResponsePtr, Answered.Result);

            uint Status = (uint)Helper.GetArg(0);
            uint Count = (uint)Helper.GetArg(1);
            uint Mask = (uint)Helper.GetArg(2);
            ulong ParametersPtr = Helper.GetArg(3);
            uint Option = (uint)Helper.GetArg(4);
            bool Is64 = Helper.PointerSize == 8;

            // NT: the WOW64 thunk passes no array when the count is 0.
            if (!Is64 && Count == 0)
                ParametersPtr = 0;

            if (Count > HardErrorHandler.MaxParameters || (ParametersPtr == 0) != (Count == 0))
                return NTSTATUS.STATUS_INVALID_PARAMETER_2;

            if (Option > MaxOption)
                return NTSTATUS.STATUS_INVALID_PARAMETER_4;

            if (!IsWritable(Instance, ResponsePtr))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Span<ulong> Parameters = stackalloc ulong[HardErrorHandler.MaxParameters];
            Span<HardErrorHandler.CapturedString> Strings = stackalloc HardErrorHandler.CapturedString[HardErrorHandler.MaxParameters];
            NTSTATUS Capture = CaptureParameters(Instance, ParametersPtr, Count, Mask, Is64, Parameters, Strings);
            if (Capture != NTSTATUS.STATUS_SUCCESS)
                return Capture;

            if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
            {
                Instance.TriggerEventMessage($"[-] NtRaiseHardError -> 0x{Status:X8}, {Count} parameters, option {Option}", LogFlags.Issues);
                if (Is64)
                    TraceFailFastRecord(Instance, Status);
                Instance.TraceCallStack("[-] NtRaiseHardError");
            }

            // Guest tokens hold no SeShutdownPrivilege, so the shutdown option always fails.
            if (Option == OptionShutdownSystem)
            {
                Reply(Instance, ResponsePtr, 0);
                return NTSTATUS.STATUS_PRIVILEGE_NOT_HELD;
            }

            if (!ReachesCsrss(Instance, Status))
                return Reply(Instance, ResponsePtr, 0);

            uint Response = HardErrorHandler.Raise(Instance, Status & ~OverrideErrorMode, Count, Mask, Parameters, Strings, Option, out Task<uint> Answer);
            if (Answer == null)
                return Reply(Instance, ResponsePtr, Response);

            Answer.ContinueWith(static (_, State) => ((BinaryEmulator)State).WakeSignal.Bump(), Instance, TaskContinuationOptions.ExecuteSynchronously);
            return Helper.TryRetrySyscallWhenDone(Answer) ? NTSTATUS.STATUS_SUCCESS : Reply(Instance, ResponsePtr, 0);
        }

        // NT: a process with SEM_FAILCRITICALERRORS, unless the status overrides it, and a thread whose
        // TEB HardErrorMode has RTL_ERRORMODE_FAILCRITICALERRORS get no box and response 0.
        private static bool ReachesCsrss(BinaryEmulator Instance, uint Status)
        {
            if ((Instance.WinHelper.DefaultHardErrorMode & ProcessShowsHardErrors) == 0 && (Status & OverrideErrorMode) == 0)
                return false;

            ulong NativeTeb = Instance.NativeTEB;
            return NativeTeb == 0 || (Instance.ReadMemoryUInt(NativeTeb + TebHardErrorMode) & ThreadFailCriticalErrors) == 0;
        }

        private static NTSTATUS Reply(BinaryEmulator Instance, ulong ResponsePtr, uint Response)
        {
            if (Response > MaxResponse)
                Response = 0;

            return Instance.WinHelper.WriteUInt32(ResponsePtr, Response) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        // NT: ProbeForWrite of the response, which reads and writes back its value.
        private static bool IsWritable(BinaryEmulator Instance, ulong Address)
        {
            Span<byte> Value = stackalloc byte[4];
            return Instance.ReadMemory(Address, Value) && Instance.WriteMemory(Address, Value);
        }

        private static NTSTATUS CaptureParameters(BinaryEmulator Instance, ulong ParametersPtr, uint Count, uint Mask, bool Is64,
            Span<ulong> Parameters, Span<HardErrorHandler.CapturedString> Strings)
        {
            if (Count == 0)
                return NTSTATUS.STATUS_SUCCESS;

            int Width = Is64 ? 8 : 4;
            if (Is64 && (ParametersPtr & 7) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            Span<byte> Slots = stackalloc byte[HardErrorHandler.MaxParameters * 8];
            Slots = Slots.Slice(0, (int)Count * Width);
            if (!Instance.ReadMemory(ParametersPtr, Slots))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Span<byte> Header = stackalloc byte[UnicodeString64Size];
            for (int i = 0; i < Count; i++)
            {
                ulong Value = Is64
                    ? BinaryPrimitives.ReadUInt64LittleEndian(Slots.Slice(i * 8))
                    : BinaryPrimitives.ReadUInt32LittleEndian(Slots.Slice(i * 4));
                Parameters[i] = Value;

                if ((Mask & (1u << i)) == 0)
                    continue;

                if (Is64 && (Value & 7) != 0)
                    return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

                Span<byte> String = Header.Slice(0, Is64 ? UnicodeString64Size : UnicodeString32Size);
                if (Value == 0 || !Instance.ReadMemory(Value, String))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                ushort Length = BinaryPrimitives.ReadUInt16LittleEndian(String);
                ulong Buffer = Is64
                    ? BinaryPrimitives.ReadUInt64LittleEndian(String.Slice(8))
                    : BinaryPrimitives.ReadUInt32LittleEndian(String.Slice(4));
                Strings[i] = new HardErrorHandler.CapturedString(Length, Buffer);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void TraceFailFastRecord(BinaryEmulator Instance, uint ErrorStatus)
        {
            const int ExceptionAddressOffset = 0x10;
            const int ScanSlots = 4096;

            ulong StackPointer = Instance.ReadRegister(Registers.UC_X86_REG_RSP);

            for (int i = 0; i < ScanSlots; i++)
            {
                ulong Slot = StackPointer + (ulong)i * 8;
                if (!Instance.IsRegionMapped(Slot, ExceptionAddressOffset + 8))
                    break;

                if ((Instance.ReadMemoryUInt(Slot) & 0x0FFFFFFF) != (ErrorStatus & 0x0FFFFFFF))
                    continue;

                ulong ExceptionAddress = Instance.ReadMemoryULong(Slot + ExceptionAddressOffset);
                if (ExceptionAddress == 0)
                    continue;

                Instance.TriggerEventMessage($"[-] NtRaiseHardError raised at {Instance.DescribeAddress(ExceptionAddress)}", LogFlags.Issues);
                return;
            }
        }
    }
}
