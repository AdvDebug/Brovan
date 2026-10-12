using System.Buffers.Binary;
using System;
using static Brovan.Core.Emulation.OS.Windows.WinSysHelper;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtRaiseException : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance == null || Instance._binary == null || Instance.WinHelper == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            bool Is64 = Instance.WinHelper.PointerSize == 8;

            ulong ExceptionRecordPtr = Instance.WinHelper.GetArg(0);
            ulong ContextRecordPtr = Instance.WinHelper.GetArg(1);

            bool FirstChance = (byte)Instance.WinHelper.GetArg(2) != 0;

            if (ExceptionRecordPtr == 0 || ContextRecordPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            int RecordSize = Is64 ? ExceptionInformation.RecordSize64 : ExceptionInformation.RecordSize32;
            if (!Instance.IsRegionMapped(ExceptionRecordPtr, (ulong)RecordSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS ContextStatus = WindowsThreadContext64.TryReadContextFlags(Instance, ContextRecordPtr, out uint ContextFlags);
            if (ContextStatus != NTSTATUS.STATUS_SUCCESS)
                return ContextStatus;

            Span<byte> Record = stackalloc byte[ExceptionInformation.RecordSize64];
            Record = Record.Slice(0, RecordSize);
            Instance.ReadMemory(ExceptionRecordPtr, Record);

            // NT clears bit 28 of the code (KiRaiseException). WOW64 dispatches a record with too many parameters anyway.
            uint ExceptionCode = BinaryPrimitives.ReadUInt32LittleEndian(Record) & ~0x10000000u;
            uint NumberParameters = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(Is64 ? 0x18 : 0x10));
            if (NumberParameters > ExceptionInformation.MaximumParameters)
            {
                if (Is64)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;
                NumberParameters = ExceptionInformation.MaximumParameters;
            }

            // With no debugger, NT ends the process on a second chance (KiDispatchException).
            if (!FirstChance)
            {
                NtTerminateProcess.TerminateCurrentProcess(Instance, ExceptionCode);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint ExceptionFlags = BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(0x04));
            ulong NestedRecord = ReadRecordPointer(Record, 0x08, Is64);
            ulong ExceptionAddress = ReadRecordPointer(Record, Is64 ? 0x10 : 0x0C, Is64);

            ulong[] Parameters = Array.Empty<ulong>();
            if (NumberParameters != 0)
            {
                int ParameterBase = Is64 ? 0x20 : 0x14;
                Parameters = new ulong[NumberParameters];
                for (int i = 0; i < (int)NumberParameters; i++)
                    Parameters[i] = ReadRecordPointer(Record, ParameterBase + i * (Is64 ? 8 : 4), Is64);
            }

            EmulatedThread CurrentThread = Instance.CurrentThread;
            if (CurrentThread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadContext64.ApplyResumeContext(Instance, CurrentThread, ContextRecordPtr, ContextFlags);

            ExceptionInformation Info = new ExceptionInformation();
            Info.Status = (NTSTATUS)ExceptionCode;
            Info.Flags = ExceptionFlags;
            Info.NestedRecord = NestedRecord;
            Info.ExceptionAddress = ExceptionAddress;
            Info.CustomParameters = Parameters;

            CurrentThread.State = EmulatedThreadState.Exception;
            WinEmulatedThread.GetState(CurrentThread).DispatchException = true;
            WinEmulatedThread.GetState(CurrentThread).ExceptionInformation = Info;
            CurrentThread.ExitCode = unchecked((int)ExceptionCode);

            Instance.Threads[(uint)Instance.CurrentThreadId] = CurrentThread;
            if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                Instance.TriggerEventMessage($"[!] NtRaiseException triggered with Exception Code: 0x{ExceptionCode:X}", LogFlags.Issues);
            WindowsThreadContext64.ResumeAtNewContext(Instance, CurrentThread);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static ulong ReadRecordPointer(ReadOnlySpan<byte> Record, int Offset, bool Is64)
            => Is64 ? BinaryPrimitives.ReadUInt64LittleEndian(Record.Slice(Offset)) : BinaryPrimitives.ReadUInt32LittleEndian(Record.Slice(Offset));
    }
}