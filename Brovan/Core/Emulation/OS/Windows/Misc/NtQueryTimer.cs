namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryTimer : IWinSyscall
    {
        // NT writes the two fields and leaves the padding alone.
        private const uint TimerBasicInformation = 0;
        private const uint BasicInformationSize = 16;
        private const ulong OffsetTimerState = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            ulong TimerHandle = Helper.GetArg(0);
            uint InformationClass = (uint)Helper.GetArg(1);
            ulong InformationPtr = Helper.GetArg(2);
            uint InformationLength = (uint)Helper.GetArg(3);
            ulong ReturnLengthPtr = Helper.GetArg(4);

            if (InformationClass != TimerBasicInformation)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            if (InformationLength != BasicInformationSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if ((InformationPtr & 3) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            if (Helper.ProbeForWrite(InformationPtr, BasicInformationSize) != NTSTATUS.STATUS_SUCCESS
                || (ReturnLengthPtr != 0 && Helper.ProbeForWrite(ReturnLengthPtr, sizeof(uint)) != NTSTATUS.STATUS_SUCCESS))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // NT checks the object type before the access.
            NTSTATUS Status = Helper.ReferenceObjectByHandle(TimerHandle, AccessMask.None, out WinTimer Timer, out AccessMask Granted);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Timer is WinIRTimer)
                return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

            if (!HandleManager.Grants(Granted, AccessMask.TimerQueryState))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            Instance.CanSatisfyWaitHandle(TimerHandle);
            if (!Helper.WriteUInt64(InformationPtr, unchecked((ulong)RemainingTime(Instance, Timer)))
                || !Helper.WriteByte(InformationPtr + OffsetTimerState, Timer.Signaled ? (byte)1 : (byte)0)
                || (ReturnLengthPtr != 0 && !Helper.WriteUInt32(ReturnLengthPtr, BasicInformationSize)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT takes the due time of an idle timer as 0, so its time left is minus the interrupt time.
        private static long RemainingTime(BinaryEmulator Instance, WinTimer Timer)
        {
            if (!Timer.Active)
                return -(long)Instance.WinHelper.KuserSharedData.CurrentInterruptTime;

            long Milliseconds = Timer.DueTick - Instance.EmulatedTickCount64;
            return Milliseconds > long.MaxValue / NtTimerHelpers.IntervalsPerMillisecond ? long.MaxValue : Milliseconds * NtTimerHelpers.IntervalsPerMillisecond;
        }
    }
}
