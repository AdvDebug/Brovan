using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetInformationWorkerFactory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong WorkerFactoryHandle = Instance.WinHelper.GetArg64(0);
            WORKERFACTORYINFOCLASS InfoClass = (WORKERFACTORYINFOCLASS)Instance.WinHelper.GetArg64(1);
            ulong WorkerFactoryInformation = Instance.WinHelper.GetArg64(2);
            uint WorkerFactoryInformationLength = (uint)Instance.WinHelper.GetArg64(3);

            WinWorkerFactory Factory = WorkerFactoryHelper.GetFactory(Instance, WorkerFactoryHandle);
            if (Factory == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (InfoClass >= WORKERFACTORYINFOCLASS.MaxWorkerFactoryInfoClass)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            if (WorkerFactoryInformation == 0 && WorkerFactoryInformationLength != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Factory.LastInfoClass = (uint)InfoClass;
            Factory.LastInfoLength = WorkerFactoryInformationLength;
            Factory.LastInfoValue = 0;

            switch (InfoClass)
            {
                case WORKERFACTORYINFOCLASS.WorkerFactoryTimeout:
                case WORKERFACTORYINFOCLASS.WorkerFactoryRetryTimeout:
                case WORKERFACTORYINFOCLASS.WorkerFactoryIdleTimeout:
                    {
                        if (WorkerFactoryInformationLength != 8)
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        long Value = unchecked((long)Instance._emulator.ReadMemoryULong(WorkerFactoryInformation));
                        Factory.LastInfoValue = unchecked((ulong)Value);
                        if (InfoClass == WORKERFACTORYINFOCLASS.WorkerFactoryTimeout)
                            Factory.Timeout = Value;
                        else if (InfoClass == WORKERFACTORYINFOCLASS.WorkerFactoryRetryTimeout)
                            Factory.RetryTimeout = Value;
                        else
                            Factory.IdleTimeout = Value;
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case WORKERFACTORYINFOCLASS.WorkerFactoryBindingCount:
                    {
                        if (WorkerFactoryInformationLength != 4)
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        uint RawValue = Instance._emulator.ReadMemoryUInt(WorkerFactoryInformation);
                        int Delta = unchecked((int)RawValue);
                        Factory.LastInfoValue = RawValue;

                        if (Delta < 0)
                        {
                            uint Decrement = (uint)(-Delta);
                            if (Decrement >= Factory.BindingCount)
                                Factory.BindingCount = 0;
                            else
                                Factory.BindingCount -= Decrement;
                        }
                        else
                        {
                            ulong Next = (ulong)Factory.BindingCount + (uint)Delta;
                            Factory.BindingCount = Next > uint.MaxValue ? uint.MaxValue : (uint)Next;
                        }

                        WorkerFactoryHelper.EnsureWorkerThreads(Instance, Factory);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                case WORKERFACTORYINFOCLASS.WorkerFactoryThreadMinimum:
                case WORKERFACTORYINFOCLASS.WorkerFactoryThreadMaximum:
                case WORKERFACTORYINFOCLASS.WorkerFactoryPaused:
                case WORKERFACTORYINFOCLASS.WorkerFactoryThreadBasePriority:
                case WORKERFACTORYINFOCLASS.WorkerFactoryTimeoutWaiters:
                case WORKERFACTORYINFOCLASS.WorkerFactoryFlags:
                case WORKERFACTORYINFOCLASS.WorkerFactoryThreadSoftMaximum:
                    {
                        if (WorkerFactoryInformationLength != 4)
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                        uint Value = Instance._emulator.ReadMemoryUInt(WorkerFactoryInformation);
                        Factory.LastInfoValue = Value;
                        switch (InfoClass)
                        {
                            case WORKERFACTORYINFOCLASS.WorkerFactoryThreadMinimum:
                                Factory.ThreadMinimum = Value;
                                break;
                            case WORKERFACTORYINFOCLASS.WorkerFactoryThreadMaximum:
                                Factory.ThreadMaximum = Value;
                                break;
                            case WORKERFACTORYINFOCLASS.WorkerFactoryPaused:
                                Factory.Paused = Value;
                                break;
                            case WORKERFACTORYINFOCLASS.WorkerFactoryThreadBasePriority:
                                Factory.ThreadBasePriority = Value;
                                break;
                            case WORKERFACTORYINFOCLASS.WorkerFactoryTimeoutWaiters:
                                Factory.TimeoutWaiters = Value;
                                break;
                            case WORKERFACTORYINFOCLASS.WorkerFactoryFlags:
                                Factory.Flags = Value;
                                break;
                            case WORKERFACTORYINFOCLASS.WorkerFactoryThreadSoftMaximum:
                                Factory.ThreadSoftMaximum = Value;
                                break;
                        }

                        WorkerFactoryHelper.EnsureWorkerThreads(Instance, Factory);
                        return NTSTATUS.STATUS_SUCCESS;
                    }

                default:
                    {
                        if (WorkerFactoryInformationLength == 0)
                            return NTSTATUS.STATUS_SUCCESS;

                        if (WorkerFactoryInformationLength == 4)
                        {
                            Factory.LastInfoValue = Instance._emulator.ReadMemoryUInt(WorkerFactoryInformation);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                        if (WorkerFactoryInformationLength == 8)
                        {
                            Factory.LastInfoValue = Instance._emulator.ReadMemoryULong(WorkerFactoryInformation);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                        return NTSTATUS.STATUS_NOT_SUPPORTED;
                    }
            }
        }
    }
}
