using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateTimer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong TimerHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
            ulong TimerType = (uint)Instance.WinHelper.GetArg(3);

            return HandleCreateTimer(Instance, TimerHandlePtr, DesiredAccess, ObjectAttributesPtr, TimerType);
        }

        private static NTSTATUS HandleCreateTimer(BinaryEmulator Instance, ulong TimerHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr, ulong TimerType)
        {
            if (TimerHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(TimerHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (TimerType > (ulong)TIMER_TYPE.SynchronizationTimer)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Instance.WinHelper.ReadCreateObjectName(ObjectAttributesPtr, out string Name, out uint Attributes);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.TryLookupNameForCreate(Name, Attributes, out WinTimer? Existing, out Status))
                return Status;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Existing != null
                ? Instance.WinHelper.OpenObjectHandle(Existing, Permissions)
                : Instance.WinHelper.CreateTimerHandle(Name, (TIMER_TYPE)TimerType, Permissions);

            if (!Instance.WinHelper.WritePointer(TimerHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Status;
        }
    }

    internal static class NtTimerHelpers
    {
        public const long IntervalsPerMillisecond = 10000;

        public static NTSTATUS SetTimer2(BinaryEmulator Instance, WinIRTimer Timer, ulong TimerHandle, long? DueTime, long Period, ReadOnlySpan<byte> Parameters)
        {
            if (Period != 0 && (Timer.Attributes & WinIRTimer.IRTimerAttribute) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Parameters.IsEmpty && (BinaryPrimitives.ReadUInt32LittleEndian(Parameters) != 0 || BinaryPrimitives.ReadInt64LittleEndian(Parameters.Slice(8)) < -1))
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            if (DueTime is not long Due)
            {
                CancelTimer(Instance, Timer);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Period != 0 && Period < NtQueryTimerResolution.FinestResolution)
                Period = NtQueryTimerResolution.FinestResolution;

            ArmTimer(Instance, Timer, TimerHandle, Instance.WinHelper.TimeoutToMilliseconds(Due), WinSysHelper.IntervalToMilliseconds(Period), out _);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // A timer that came due before the cancel keeps its signal, as on NT.
        public static void CancelTimer(BinaryEmulator Instance, WinTimer Timer)
        {
            Instance.RefreshTimer(Timer);
            Timer.Active = false;
            ClearTimerApc(Instance, Timer);
            Instance.InvalidateWindowsTimerDue();
        }

        public static void SetTimerApc(BinaryEmulator Instance, WinTimer Timer, ulong ApcRoutine, ulong ApcContext)
        {
            ClearTimerApc(Instance, Timer);
            if (ApcRoutine == 0)
                return;

            Timer.ApcThread = Instance.CurrentThread;
            Timer.ApcRoutine = ApcRoutine;
            Timer.ApcContext = ApcContext;
            Instance.WinHelper.ApcTimers.Add(Timer);
        }

        public static void ClearTimerApc(BinaryEmulator Instance, WinTimer Timer)
        {
            if (Timer.ApcThread == null)
                return;

            if (Timer.QueuedApc != null)
                WinEmulatedThread.GetState(Timer.ApcThread).PendingUserApcs.Remove(Timer.QueuedApc);

            Instance.WinHelper.ApcTimers.Remove(Timer);
            Timer.ApcThread = null;
            Timer.ApcRoutine = 0;
            Timer.ApcContext = 0;
            Timer.QueuedApc = null;
        }

        public static void RundownTimers(BinaryEmulator Instance, EmulatedThread Thread)
        {
            List<WinTimer> Timers = Instance.WinHelper.ApcTimers;
            for (int i = Timers.Count - 1; i >= 0; i--)
            {
                if (Timers[i].ApcThread == Thread)
                    CancelTimer(Instance, Timers[i]);
            }
        }

        public static void ArmTimer(BinaryEmulator Instance, WinTimer Timer, ulong TimerHandle, long DueMilliseconds, long PeriodMilliseconds, out bool WasSignaled)
        {
            WasSignaled = Timer.Signaled;
            Timer.Signaled = false;
            Timer.Active = true;
            Timer.DueTick = Instance.CreateEmulatedDeadlineMilliseconds(DueMilliseconds);
            Timer.PeriodMilliseconds = PeriodMilliseconds;
            Instance.InvalidateWindowsTimerDue();

            if (DueMilliseconds == 0)
            {
                Timer.Signaled = true;
                Instance.QueueTimerApc(Timer);
                if (Timer.PeriodMilliseconds == 0)
                    Timer.Active = false;
                else
                    Timer.DueTick = Instance.CreateEmulatedDeadlineMilliseconds(Timer.PeriodMilliseconds);

                if (Instance.WakeWorkerFactoryWaitersForObject(TimerHandle) || Instance.HasHandleWaiters(TimerHandle))
                    Instance._emulator.StopEmulation();
            }
        }

        public static NTSTATUS WritePreviousState(BinaryEmulator Instance, ulong PreviousStatePtr, bool WasSignaled)
        {
            if (PreviousStatePtr == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (!Instance.IsRegionMapped(PreviousStatePtr, 1))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance._emulator.WriteMemory(PreviousStatePtr, (byte)(WasSignaled ? 1 : 0)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
